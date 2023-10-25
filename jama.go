//go:build linux && amd64

package jama

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TODO: WTF is line 72 and onwards???

// TODO: communication between parent and child and API for controlling what
// fails/manipulating things arbitrarily.

// TODO: can we skip actually doing the syscall and allow the users of mocking
// the whole syscall?

// TODO: support for more platforms

// jamaChildEnv is the name of the environment variable used to signal that
// we're running in the child process which should be traced.
const jamaChildEnv = "JAMA_CHILD"

var (
	// m is the global mutator. Only used in the client process.
	m mutator = nil
	// mu protects m.
	mu sync.Mutex
)

// TODO: Do I panic, or just lock?

// WithGlobal calls f with mf active for all goroutines. It cannot be used
// concurrently with any other With* calls, including other calls of itself.
func WithGlobal(mf MutatorFunc, f func()) {
	mu.Lock()
	if m != nil {
		mu.Unlock()
		panic("jama: WithGlobal: called while other mutation was already active")
	}
	m = globalMutator(mf)
	mu.Unlock()

	f()

	mu.Lock()
	m = nil
	mu.Unlock()
}

// WithLocal calls f with mf active for the current goroutine. If f creates new
// goroutines, mf will not apply to them. It cannot be used concurrently with
// any other With* calls, and cannot be nested within calls to itself (i.e. f
// cannot call WithLocal).
func WithLocal(mf MutatorFunc, f func()) {
	// Necessary so the goroutine that f is executed on is guaranteed to match
	// the tid below.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid := unix.Gettid()

	mu.Lock()

	var perTID perTIDMutator
	var ok bool
	if m == nil {
		// If there was no active mutator, create a new per-TID mutator.
		perTID = perTIDMutator{}
		m = perTID
	} else if perTID, ok = m.(perTIDMutator); !ok {
		// If there was an active mutator but it wasn't per-TID, panic.
		mu.Unlock()
		panic("jama: WithLocal: called while global mutation was already active")
	}

	if _, ok := perTID[tid]; ok {
		mu.Unlock()
		panic("jama: WithLocal: called while mutation for this goroutine was already active")
	}

	perTID[tid] = mf
	mu.Unlock()

	f()

	mu.Lock()
	delete(perTID, tid)
	if len(perTID) == 0 {
		m = nil
	}
	mu.Unlock()
}

// isPtraceStop returns whether status indicates that the process/thread was
// stopped by ptrace.
func isPtraceStop(status unix.WaitStatus) bool {
	// The |0x80 specifically indicates that this change was triggered by
	// ptrace, as requested by out use of the PTRACE_O_TRACESYSGOOD option.
	return status.StopSignal() == unix.SIGTRAP|0x80
}

// isEventClone returns whether status indicates that the process/thread was
// stopped due to a pthread clone event.
func isEventClone(status unix.WaitStatus) bool {
	return status.Stopped() &&
		status>>8 == unix.WaitStatus(unix.SIGTRAP|unix.PTRACE_EVENT_CLONE<<8)
}

func init() {
	const (
		CLIENTR_FD = iota + 3 // stdin, stdout, and stderr take up 1, 2, and 3.
		CLIENTW_FD
	)

	// Protocol types.
	type (
		childMutatorTID int
		ipcActive       struct{}
		regsAndTID      struct {
			Regs unix.PtraceRegs
			TID  int
		}
	)

	mutatorID := childMutatorTID(0)
	gob.Register(&mutatorID)
	gob.Register(&ipcActive{})
	gob.Register(&regsAndTID{})
	gob.Register(&unix.PtraceRegs{})

	if _, found := os.LookupEnv(jamaChildEnv); found {
		introDone := make(chan struct{})
		go func() {
			// Lock this thread so we can stop tracing only it in the parent.
			runtime.LockOSThread()

			dec := gob.NewDecoder(io.TeeReader(os.NewFile(CLIENTR_FD, "jama-read.pipe"), os.Stdout))
			enc := gob.NewEncoder(os.NewFile(CLIENTW_FD, "jama-write.pipe"))

			tid := unix.Gettid()
			msg := childMutatorTID(tid)
			fmt.Println("child is tid:", tid)
			if err := enc.Encode(&msg); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			fmt.Println("waiting for active")

			var a ipcActive
			if err := dec.Decode(&a); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// TODO: We've got a problem with proceeding. We can't exit init
			// until we know that ipc and stuff is active, but that stuff can't
			// be active until we know that this routine will be ready to accept
			// stuff...

			fmt.Println("marking intro done")
			introDone <- struct{}{}
			fmt.Println("done intro")

			for {
				fmt.Println("decoding child")

				var asdf regsAndTID
				if err := dec.Decode(&asdf); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}

				fmt.Println("decoded child")

				mu.Lock()
				if m != nil {
					m.mutate(asdf.TID, &asdf.Regs)
				}
				mu.Unlock()

				fmt.Println("encoding child")

				if err := enc.Encode(&asdf.Regs); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}

				fmt.Println("encoded child")
			}
		}()
		<-introDone

		// Continue usual program execution with ptrace now active.
		return
	}

	// If not set, we're in the parent, so start a child that will take the
	// branch above and become ptrace'd by us.

	// Create files and pipes to be used by child.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	clientR, parentW, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	parentR, clientW, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	enc := gob.NewEncoder(parentW)
	dec := gob.NewDecoder(parentR)

	// Necessary because only the thread that spawns the process below which
	// will call PTRACE_TRACEME on startup will have permission to contorol it,
	// so unless we do this, we risk getting rescheduled to another OS thread
	// on which PTRACE_* operations would fail and cause everything to break.
	runtime.LockOSThread()

	proc, err := os.StartProcess(os.Args[0], os.Args, &os.ProcAttr{
		Files: []*os.File{
			devNull, os.Stdout, os.Stderr,
			CLIENTR_FD: clientR, CLIENTW_FD: clientW,
		},
		Env: append(os.Environ(), jamaChildEnv+"=1"),
		Sys: &syscall.SysProcAttr{Ptrace: true},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pid := proc.Pid

	// Wait for the child to stop itself when it reaches the branch above.
	var status unix.WaitStatus
	if _, err := unix.Wait4(pid, &status, 0, nil); err != nil {
		// TODO: handle other potential status changes here so we're guaranteed
		// to be ptrace-stopped when we get to below.

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// We need PTRACE_O_TRACECLONE so we can monitor all goroutines and
	// PTRACE_O_TRACESYSGOOD so we can precisely detect when a SIGTRAP was
	// caused by ptrace.
	options := unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACESYSGOOD
	if err := unix.PtraceSetOptions(pid, options); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var serverTID atomic.Int64
	go func() {
		var tid childMutatorTID
		if err := dec.Decode(&tid); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// // Stop tracing the server thread of the child so it never gets stopped.
		// if err := syscall.PtraceDetach(int(tid)); err != nil {
		// 	fmt.Fprintln(os.Stderr, err)
		// 	os.Exit(1)
		// }

		serverTID.Store(int64(tid))

		if err := enc.Encode(&ipcActive{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		fmt.Println("yoo")
	}()

	lastTID := pid
	serverDetached := false
	for {
		fmt.Println("here1")

		// Allow the child to continue until the next syscall entry or exit, at
		// which point it will be stopped. Ignore ESRCH since the only way this
		// can fail is if lastTID has been killed between the end of the wait
		// and now.
		if err := unix.PtraceSyscall(lastTID, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		fmt.Println("here2")

		// Wait until we get a relevant state change.
		var status unix.WaitStatus
		for {
			var err error
			lastTID, err = unix.Wait4(-1, &status, 0, nil)
			fmt.Println("here3")
			if err != nil {
				if err == unix.EINTR {
					// Keep going until the wait succeeds.
					continue
				}

				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			if status.Stopped() {
				if isPtraceStop(status) || isEventClone(status) {
					// Jump out of the inner loop to examine the syscall.
					break
				} else {
					// Deliver the stop signal and allow the process to
					// continue.
					if err := unix.PtraceSyscall(lastTID, int(status.StopSignal())); err != nil {
						if errors.Is(err, unix.ESRCH) {
							// TODO: What do we do about this shit?
							fmt.Println("lasdjkfslk", status.StopSignal())
							continue
						}

						fmt.Fprintln(os.Stderr, err)
						os.Exit(1)
					}
					continue
				}
			}

			// If the whole child (not just one of its threads) exited, then we
			// should exit too because there's nothing left to do.
			if lastTID == pid {
				switch {
				case status.Exited():
					os.Exit(status.ExitStatus())

				case status.Signaled():
					// Format copied from (*os.ProcessState).String.
					msg := "signal: " + status.Signal().String()
					if status.CoreDump() {
						msg += " (core dumped)"
					}

					fmt.Fprintln(os.Stderr, msg)
					os.Exit(1)
				}
			}
		}

		fmt.Println("here4")

		// PTRACE_GET_SYSCALL_INFO actually returns a big struct, but op is the
		// first field, and the data is truncated if there's not space for it,
		// so since we only need op, we do this to avoid having to get
		// definitions for the whole struct.
		var op uint8
		_, _, err := unix.Syscall6(unix.SYS_PTRACE,
			unix.PTRACE_GET_SYSCALL_INFO, uintptr(lastTID), unsafe.Sizeof(op),
			uintptr(unsafe.Pointer(&op)), 0, 0)
		if err != 0 {
			if err == unix.ESRCH {
				// Process could've been killed since the syscall-stop.
				continue
			}

			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if op != unix.PTRACE_SYSCALL_INFO_EXIT {
			// We only act on syscall exits.
			continue
		}

		fmt.Println("here5", lastTID)

		serverTID := serverTID.Load()
		if serverTID == 0 {
			continue
		} else if !serverDetached {
			fmt.Println("detaching")
			if err := syscall.PtraceDetach(int(serverTID)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		// Fetch regs.
		var regs unix.PtraceRegs
		if err := unix.PtraceGetRegs(lastTID, &regs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Mutate regs over rpc.
		fmt.Println("encoding parent")
		if err := enc.Encode(&regsAndTID{regs, lastTID}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("encoded parent")
		fmt.Println("decoding parent")
		var mregs unix.PtraceRegs
		if err := dec.Decode(&mregs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("decoded parent")

		// Set regs if mutated.
		if regs != mregs {
			if err := unix.PtraceSetRegs(lastTID, &mregs); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}
