//go:build linux && amd64

package jama

import (
	"encoding/gob"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

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
	return status.Stopped() && status.StopSignal() == unix.SIGTRAP|0x80
}

// isEventClone returns whether status indicates that the process/thread was
// stopped due to a pthread clone event.
func isEventClone(status unix.WaitStatus) bool {
	return status.Stopped() &&
		status>>8 == unix.WaitStatus(unix.SIGTRAP|unix.PTRACE_EVENT_CLONE<<8)
}

func init() {
	gob.Register(unix.PtraceRegs{})

	if _, found := os.LookupEnv(jamaChildEnv); found {
		// // Stop self and wait for parent to take control via ptrace.
		// if err := unix.Kill(unix.Getpid(), unix.SIGSTOP); err != nil {
		// 	fmt.Fprintln(os.Stderr, err)
		// 	os.Exit(1)
		// }

		// TODO: start rpc?

		// Continue usual program execution with ptrace now active.
		return
	}

	// If not set, we're in the parent, so start a child that will take the
	// branch above and become ptrace'd by us.

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Necessary because only the thread that spawns the process below which
	// will call PTRACE_TRACEME on startup will have permission to contorol it,
	// so unless we do this, we risk getting rescheduled to another OS thread
	// on which PTRACE_* operations would fail and cause everything to break.
	runtime.LockOSThread()

	proc, err := os.StartProcess(os.Args[0], os.Args, &os.ProcAttr{
		Files: []*os.File{devNull, os.Stdout, os.Stderr},
		Env:   append(os.Environ(), jamaChildEnv+"=1"),
		Sys:   &syscall.SysProcAttr{Ptrace: true},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pid := proc.Pid

	// Wait for the child to stop itself when it reaches the branch above.
	var status unix.WaitStatus
	if _, err := unix.Wait4(pid, &status, 0, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// We need traceclone so we can monitor all goroutines.
	options := unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACESYSGOOD
	if err := unix.PtraceSetOptions(pid, options); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	lastTid := pid
	for {
		// Allow the child to continue until the next syscall entry or exit, at
		// which point it will be stopped.
		if err := unix.PtraceSyscall(lastTid, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Wait until we get a relevant state change.
		var status unix.WaitStatus
		for {
			var err error
			lastTid, err = unix.Wait4(-1, &status, unix.WUNTRACED, nil)
			if err != nil {
				if err == unix.EINTR {
					continue
				}

				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			if isPtraceStop(status) || isEventClone(status) {
				break
			}

			// If the whole child (not just one of its threads) exited, then we
			// should exit too because there's nothing left to do.
			if lastTid == pid {
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

		if isEventClone(status) {
			// Find out the name of the new thread and resume it.
			newTid, err := unix.PtraceGetEventMsg(lastTid)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			if err := unix.PtraceSyscall(int(newTid), 0); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			continue
		}

		// PTRACE_GET_SYSCALL_INFO actually returns a big struct, but op is the
		// first field, and the data is truncated if there's not space for it,
		// so since we only need op, we do this to avoid having to get
		// definitions for the whole struct.
		var op uint8
		_, _, err := unix.Syscall6(unix.SYS_PTRACE,
			unix.PTRACE_GET_SYSCALL_INFO, uintptr(lastTid), unsafe.Sizeof(op),
			uintptr(unsafe.Pointer(&op)), 0, 0)
		if err != 0 {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if op != unix.PTRACE_SYSCALL_INFO_EXIT {
			// We only act on syscall exits.
			continue
		}

		var regs unix.PtraceRegs
		if err := unix.PtraceGetRegs(lastTid, &regs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// TODO: mutate regs over rpc
		mregs := regs

		if regs != mregs {
			if err := unix.PtraceSetRegs(lastTid, &mregs); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}
