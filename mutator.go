//go:build linux && amd64

package jama

import "golang.org/x/sys/unix"

// MutatorFunc is a function that mutates regs.
type MutatorFunc func(regs *unix.PtraceRegs)

// mutator provides a method for mutating regs.
type mutator interface {
	// mutate regs, which belong to the given tid.
	mutate(tid int, regs *unix.PtraceRegs)
}

// globalMutator applies the same thread mutation to all TIDs.
type globalMutator MutatorFunc

// mutate implements mutator.
func (m globalMutator) mutate(tid int, regs *unix.PtraceRegs) { m(regs) }

// perTIDMutator mutates registers on a per-TID basis.
type perTIDMutator map[int]MutatorFunc

// mutate implements mutator.
func (m perTIDMutator) mutate(tid int, regs *unix.PtraceRegs) {
	mf, ok := m[tid]
	if !ok {
		return
	}

	mf(regs)
}

// Ensure mutators implement interface.
var (
	_ mutator = globalMutator(nil)
	_ mutator = perTIDMutator{}
)
