//go:build linux && amd64

package jama

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
)

// TODO: Handle panics in child, they seem to kill the server which deadlocks
// things...

// TODO: Can we skip actually doing the syscall and allow the users of mocking
// the whole syscall?

// TODO: Support for more platforms.

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
	logger.Debug("installing global")
	mu.Lock()
	if m != nil {
		mu.Unlock()
		panic("jama: WithGlobal: called while other mutation was already active")
	}
	m = globalMutator(mf)
	mu.Unlock()
	logger.Debug("global installed")

	f()

	logger.Debug("uninstalling global")
	mu.Lock()
	m = nil
	mu.Unlock()
	logger.Debug("global uninstalled")
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

	logger.Debug("installing local", slog.Int("tid", tid))
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
	logger.Debug("local installed", slog.Int("tid", tid))

	f()

	logger.Debug("uninstalling local", slog.Int("tid", tid))
	mu.Lock()
	delete(perTID, tid)
	if len(perTID) == 0 {
		m = nil
	}
	mu.Unlock()
	logger.Debug("local uninstalled", slog.Int("tid", tid))
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
	return status>>8 == unix.WaitStatus(unix.SIGTRAP|unix.PTRACE_EVENT_CLONE<<8)
}

func require(msg string, err error) {
	if err != nil {
		logger.Error(msg, err.Error())
		os.Exit(1)
	}
}

func requireErrno(msg string, errno syscall.Errno) {
	if errno != 0 {
		logger.Error(msg, errno.Error())
		os.Exit(1)
	}
}

func init() {
	level.Set(defaultLevel)

	const (
		CLIENTR_FD = iota + 3 // stdin, stdout, and stderr take up 0, 1, and 2.
		CLIENTW_FD
	)

	// Protocol types.
	type (
		childMutatorTID int
		regsAndTID      struct {
			Regs unix.PtraceRegs
			TID  int
		}
	)

	mutatorID := childMutatorTID(0)
	gob.Register(&mutatorID)
	gob.Register(&regsAndTID{})
	gob.Register(&unix.PtraceRegs{})

	if _, found := os.LookupEnv(jamaChildEnv); found {
		logger.Debug("child started", slog.Int("pid", os.Getpid()))

		introDone := make(chan struct{})
		go func() {
			// Lock this thread so we can stop tracing only it in the parent.
			runtime.LockOSThread()

			logger.Debug("server started", slog.Int("tid", unix.Gettid()))

			dec := gob.NewDecoder(os.NewFile(CLIENTR_FD, "jama-read.pipe"))
			enc := gob.NewEncoder(os.NewFile(CLIENTW_FD, "jama-write.pipe"))

			require("unix.Kill", unix.Kill(unix.Gettid(), unix.SIGTRAP))
			close(introDone)

			logger.Debug("server entering loop")

			for {
				var asdf regsAndTID
				require("(*gob.Decoder).Decode", dec.Decode(&asdf))

				mu.Lock()
				if m != nil {
					m.mutate(asdf.TID, &asdf.Regs)
				}
				mu.Unlock()

				require("(*gob.Encoder).Encode", enc.Encode(&asdf.Regs))
			}
		}()
		<-introDone
		logger.Debug("child init finished")
		return
	}

	logger.Debug("parent started", slog.Int("pid", os.Getpid()))

	// If not set, we're in the parent, so start a child that will take the
	// branch above and become ptrace'd by us.

	// Create files and pipes to be used by child.
	devNull, err := os.Open(os.DevNull)
	require("os.Open", err)

	clientR, parentW, err := os.Pipe()
	require("os.Pipe", err)

	parentR, clientW, err := os.Pipe()
	require("os.Pipe", err)

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
	require("os.StartProcess", err)
	pid := proc.Pid

	// Wait for the child to stop itself when it reaches the branch above.
	var status unix.WaitStatus
	_, err = unix.Wait4(pid, &status, 0, nil)
	require("unix.Wait4", err)

	// We need PTRACE_O_TRACECLONE so we can monitor all goroutines and
	// PTRACE_O_TRACESYSGOOD so we can precisely detect when a SIGTRAP was
	// caused by ptrace.
	options := unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACESYSGOOD
	require("unix.PtraceSetOptions", unix.PtraceSetOptions(pid, options))

	lastTID := pid
	serverDetached := false
	var serverTID int
	serverDied := false
	for {
		// Allow the child to continue until the next syscall entry or exit, at
		// which point it will be stopped. Ignore ESRCH since the only way this
		// can fail is if lastTID has been killed between the end of the wait
		// and now.
		if err := unix.PtraceSyscall(lastTID, 0); !errors.Is(err, unix.ESRCH) {
			require("unix.PtraceSyscall", err)
		}

		// Wait until we get a relevant state change.
		var status unix.WaitStatus
		for {
			var err error
			// TODO: will -1 catch grandchildren too...?
			lastTID, err = unix.Wait4(-1, &status, 0, nil)
			if err == unix.EINTR {
				// Keep going until the wait succeeds.
				continue
			}
			require("unix.Wait4", err)
			logger.Debug("unix.Wait4", slog.Int("tid", lastTID), slog.String("status", fmt.Sprintf("%#x", uint32(status))))

			if status.Stopped() {
				if isPtraceStop(status) || isEventClone(status) {
					// Jump out of the inner loop to examine the syscall.
					break
				} else if !serverDetached && status.StopSignal() == unix.SIGTRAP {
					require("unix.PtraceDetach", unix.PtraceDetach(lastTID))
					logger.Debug("server detached", slog.Int("tid", lastTID))

					require("unix.Kill", unix.Kill(lastTID, unix.SIGCONT))

					serverDetached = true
					continue
				} else {
					// Deliver the stop signal and allow the process to
					// continue.
					err := unix.PtraceSyscall(lastTID, int(status.StopSignal()))
					// Ignore ESRCH since lastTID may have been killed between
					// us being told about the stop signal and now.
					if !errors.Is(err, unix.ESRCH) {
						require("unix.PtraceSyscall", err)
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

			if lastTID == serverTID {
				if status.Exited() || status.Signaled() {
					// TODO: we should probably just kill the child if this
					// happens, right?
					serverDied = true
				}
			}
		}

		// PTRACE_GET_SYSCALL_INFO actually returns a big struct, but op is the
		// first field, and the data is truncated if there's not space for it,
		// so since we only need op, we do this to avoid having to get
		// definitions for the whole struct.
		var op uint8
		_, _, err := unix.Syscall6(unix.SYS_PTRACE,
			unix.PTRACE_GET_SYSCALL_INFO, uintptr(lastTID), unsafe.Sizeof(op),
			uintptr(unsafe.Pointer(&op)), 0, 0)
		if err == unix.ESRCH {
			// Process could've been killed since the syscall-stop.
			continue
		}
		requireErrno("unix.Syscall6, unix.SYS_PTRACE", err)
		logger.Debug("unix.Syscall6, unix.SYS_PTRACE", slog.Any("op", op))

		if op != unix.PTRACE_SYSCALL_INFO_EXIT {
			// We only act on syscall exits.
			continue
		}

		if !serverDetached || serverDied {
			continue
		}

		// Fetch regs.
		var regs unix.PtraceRegs
		require("unix.PtraceGetRegs", unix.PtraceGetRegs(lastTID, &regs))
		logger.Debug("unix.PtraceGetRegs", slog.Any("regs", regs))

		// Mutate regs over rpc.
		require("(*gob.Encoder).Encode", enc.Encode(&regsAndTID{regs, lastTID}))
		var mregs unix.PtraceRegs
		require("(*gob.Decoder).Decode", dec.Decode(&mregs))
		logger.Debug("got mutated regs from rpc", slog.Any("mregs", mregs))

		// Set regs if mutated.
		if regs != mregs {
			require("unix.PtraceSetRegs", unix.PtraceSetRegs(lastTID, &mregs))
		}
	}
}
