//go:build linux && amd64

package jama

import (
	"encoding/gob"
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"
	"syscall"

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
	mu.Unlock()
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
	fmt.Println(pid)

	// Wait for the child to stop itself when it reaches the branch above.
	var status unix.WaitStatus
	if _, err := unix.Wait4(pid, &status, unix.WSTOPPED, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(status.Stopped())
	fmt.Println(status.StopSignal())
	// We need traceclone so we can monitor all goroutines
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACECLONE); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// fmt.Println("here2")

	// Keep track of whether we're entering or exiting a syscall.
	var isExit = true
	for {
		// fmt.Println("here3")
		// entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		// if err != nil {
		// 	fmt.Fprintln(os.Stderr, err)
		// 	os.Exit(1)
		// }
		// for _, entry := range entries {
		// 	// fmt.Println(entry.Name())
		// }

		// Allow the child to continue until the next syscall entry or exit, at
		// which point it will be stopped.
		if err := unix.PtraceSyscall(pid, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// fmt.Println("here4")

		// Wait until the process changes state.
		var status unix.WaitStatus
		pid_, err := unix.Wait4(pid, &status, 0, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("here5", pid_)
		if int(status)>>8 == (int(unix.SIGTRAP) | (unix.PTRACE_EVENT_CLONE << 8)) {
			// fmt.Println("gottem")
			msg, err := unix.PtraceGetEventMsg(pid)
			if err != nil {
				panic(err)
			}
			fmt.Println("message was:", msg)
		}
		switch {
		case status.Stopped():
			switch {
			case status.StopSignal() == unix.SIGTRAP:

			default:
				// TODO: this happens sometimes, ignore?
				// Also, look at TRACESYSGOOD?
				fmt.Fprintf(os.Stderr, "jama: child was stopped with unexpected signal 0x%x, an outside process may be interfering", int(status.StopSignal()))
				isExit = !isExit
				// panic(fmt.Sprintf("jama: child was stopped with unexpected signal 0x%x, an outside process may be interfering", int(status.StopSignal())))
			}

			// Continue to inspection below.

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

		case status.Continued():
			// This should never happen. If it does, that means someone else is
			// interfering with the child, and we're not going to be able to
			// handle that correctly, so just fail noisily.
			panic("jama: child was unexpectedly continued, an outside process may be interfering")

		default:
			panic(fmt.Sprintf("jama: unhandled process state: %x", status))
		}

		// If the prior inspection was the exit of a syscall, then next time the
		// process stops will be the entry to a syscall, and vice versa.
		isExit = !isExit
		if !isExit {
			continue
		}

		var regs unix.PtraceRegs
		if err := unix.PtraceGetRegs(pid, &regs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if regs.Orig_rax == unix.SYS_NEWFSTATAT {
			// TODO: Provide a nice API for controlling what to complain
			// about. Ideally we should provide something that can just
			// mutate all of regs for people that want to do custom stuff,
			// but then provide convenience functions built on that that do
			// things like fail for specific syscalls. The best way to do
			// this from a control-flow perspective would probably be to
			// have a jama.WithStatFail(f func()) sort of thing. The biggest
			// probably if we want a really flexible API is how to allow
			// that if the child is stopped during the syscall handling. We
			// could make them define things up front in the Init maybe but
			// that wouldn't be the most ergonomic.

			regs.Rax = uint64((unix.ENOENT ^ math.MaxUint64) + 1)
			if err := unix.PtraceSetRegs(pid, &regs); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}
