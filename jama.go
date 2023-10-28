//go:build linux && amd64

package jama

import (
	"encoding/gob"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TODO: Can we skip actually doing the syscall and allow the users of mocking
// the whole syscall?

// TODO: Support for more platforms.

func Register(m Mutator) { gob.Register(m) }

// WithGlobal calls f with mf active for all goroutines. It cannot be used
// concurrently with any other With* calls, including other calls of itself.
func WithGlobal(m Mutator, f func()) {
	clientMu.Lock()
	require("(*gob.Encoder).Encode", clientEnc.Encode(
		Ptr(any(&SetGlobal{Mutator: m})),
	))
	var ack Ack
	require("(*gob.Decoder).Decode", clientDec.Decode(&ack))
	clientMu.Unlock()

	f()

	clientMu.Lock()
	require("(*gob.Encoder).Encode", clientEnc.Encode(Ptr(any(&RemoveGlobal{}))))
	require("(*gob.Decoder).Decode", clientDec.Decode(&ack))
	clientMu.Unlock()
}

// WithLocal calls f with m active for the current goroutine. If f creates new
// goroutines, m will not apply to them. It cannot be used concurrently with any
// other With* calls, and cannot be nested within calls to itself (i.e. f cannot
// call WithLocal).
func WithLocal(m Mutator, f func()) {
	// Necessary so the goroutine that f is executed on is guaranteed to match
	// the tid below.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid := unix.Gettid()

	clientMu.Lock()
	require("(*gob.Encoder).Encode", clientEnc.Encode(
		Ptr(any(&SetLocal{TID: tid, Mutator: m})),
	))
	var ack Ack
	require("(*gob.Decoder).Decode", clientDec.Decode(&ack))
	clientMu.Unlock()

	f()

	clientMu.Lock()
	require("(*gob.Encoder).Encode", clientEnc.Encode(
		Ptr(any(&RemoveLocal{TID: tid})),
	))
	require("(*gob.Decoder).Decode", clientDec.Decode(&ack))
	clientMu.Unlock()
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

var (
	// clientMu protects clientDec and clientEnc, since they must be locked for each
	// read/write operation pair to ensure that the received read actually
	// corresponds to the write.
	clientMu sync.Mutex

	clientEnc *gob.Encoder
	clientDec *gob.Decoder
)

func Init() {
	const (
		jamaChildEnv = "JAMA_CHILD"

		CLIENTW_FD = iota + 3 // stdin, stdout, and stderr take up 0, 1, and 2.
		CLIENTR_FD
	)

	gob.Register(SetGlobal{})
	gob.Register(RemoveGlobal{})
	gob.Register(SetLocal{})
	gob.Register(RemoveLocal{})
	gob.Register(Ack{})

	level.Set(defaultLevel)

	if _, found := os.LookupEnv(jamaChildEnv); found {
		logger.Debug("child started", slog.Int("pid", os.Getpid()))

		clientEnc = gob.NewEncoder(os.NewFile(CLIENTW_FD, "jama-write.pipe"))
		clientDec = gob.NewDecoder(os.NewFile(CLIENTR_FD, "jama-read.pipe"))

		return
	}

	// If not set, we're in the parent, so start a child that will take the
	// branch above and become ptrace'd by us.

	logger.Debug("parent started", slog.Int("pid", os.Getpid()))

	// Create files and pipes to be used by child.
	devNull, err := os.Open(os.DevNull)
	require("os.Open", err)

	parentR, clientW, err := os.Pipe()
	require("os.Pipe", err)

	clientR, parentW, err := os.Pipe()
	require("os.Pipe", err)

	dec := gob.NewDecoder(parentR)
	enc := gob.NewEncoder(parentW)

	// Necessary because only the thread that spawns the process below which
	// will call PTRACE_TRACEME on startup will have permission to contorol it,
	// so unless we do this, we risk getting rescheduled to another OS thread
	// on which PTRACE_* operations would fail and cause everything to break.
	runtime.LockOSThread()

	// Start the child.
	proc, err := os.StartProcess(os.Args[0], os.Args, &os.ProcAttr{
		Files: []*os.File{
			devNull, os.Stdout, os.Stderr,
			CLIENTW_FD: clientW, CLIENTR_FD: clientR,
		},
		Env: append(os.Environ(), jamaChildEnv+"=1"),
		Sys: &syscall.SysProcAttr{Ptrace: true},
	})
	require("os.StartProcess", err)
	pid := proc.Pid

	// Close pipes cause the parent shouldn't be writing to them anymore.
	require("(*os.File).Close", clientW.Close())
	require("(*os.File).Close", clientR.Close())

	// Start communication routine.
	var (
		mu sync.Mutex
		mp mutatorProvider = nil
	)
	go func() {
		for {
			var m any
			require("(*gob.Decoder).Decode", dec.Decode(&m))
			mu.Lock()
			switch m := m.(type) {
			case SetGlobal:
				if mp == nil {
					mp = globalMutatorProvider{inner: m}
				} else {
					require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
					panic("jama: WithGlobal: called while other mutation was already active")
				}

			case RemoveGlobal:
				if mp != nil {
					if _, ok := mp.(globalMutatorProvider); ok {
						mp = nil
					} else {
						require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
						panic("jama: WithGlobal: exited while non-global mutation was active")
					}
				} else {
					require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
					panic("jama: WithGlobal: exited while no mutation was active")
				}

			case SetLocal:
				if mp == nil {
					mp = localMutatorProvider{m.TID: m.Mutator}
				} else if mp, ok := mp.(localMutatorProvider); ok {
					if _, ok := mp[m.TID]; !ok {
						mp[m.TID] = m.Mutator
					} else {
						require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
						panic("jama: WithLocal: called while mutation for this goroutine was already active")
					}
				} else {
					require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
					panic("jama: WithLocal: called while global mutation was already active")
				}

			case RemoveLocal:
				if mp != nil {
					if lmp, ok := mp.(localMutatorProvider); ok {
						if _, ok := lmp[m.TID]; ok {
							delete(lmp, m.TID)
							if len(lmp) == 0 {
								mp = nil
							}
						} else {
							require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
							panic("jama: WithLocal: exited while no mutation for this goroutine was active")
						}
					} else {
						require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
						panic("jama: WithLocal: exited while non-local mutation was active")
					}
				} else {
					require("unix.Kill", unix.Kill(pid, unix.SIGKILL))
					panic("jama: WithLocal: exited while no mutation was active")
				}

			default:
				mu.Unlock()
				panic("unexpected message")
			}
			mu.Unlock()

			require("(*gob.Encoder).Encode", enc.Encode(Ack{}))
		}
	}()

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

		// Fetch regs.
		var regs unix.PtraceRegs
		require("unix.PtraceGetRegs", unix.PtraceGetRegs(lastTID, &regs))
		logger.Debug("unix.PtraceGetRegs", slog.Any("regs", regs))

		// Mutate regs.
		mregs := regs
		mu.Lock()
		if mp != nil {
			mp.mutatorForTID(lastTID).Mutate(&mregs)
		}
		mu.Unlock()

		// Set regs if mutated.
		if regs != mregs {
			require("unix.PtraceSetRegs", unix.PtraceSetRegs(lastTID, &mregs))
		}
	}
}
