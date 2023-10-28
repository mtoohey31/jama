package jama

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Ptr returns a pointer that points to v.
func Ptr[T any](v T) *T { return &v }

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

// require ensures that err is nil, or logs an error and exits otherwise.
func require(msg string, err error) {
	if err != nil {
		logger.Error(msg, "err", err.Error())
		os.Exit(1)
	}
}

// requireIgnoreESRCH ensures that err is nil or unix.ESRCH, or logs an error
// and exits otherwise.
func requireIgnoreESRCH(msg string, err error) {
	if err != nil && !errors.Is(err, unix.ESRCH) {
		logger.Error(msg, "err", err.Error())
		os.Exit(1)
	}
}

// requireErrno ensures that errno is 0, or logs an error and exits otherwise.
func requireErrno(msg string, errno syscall.Errno) {
	if errno != 0 {
		logger.Error(msg, "err", errno.Error())
		os.Exit(1)
	}
}

// requireErrnoIgnoreESRCH ensures that errno is 0 or unix.ESRCH, or logs an
// error and exits otherwise.
func requireErrnoIgnoreESRCH(msg string, errno syscall.Errno) {
	if errno != 0 && errno != unix.ESRCH {
		logger.Error(msg, "err", errno.Error())
		os.Exit(1)
	}
}
