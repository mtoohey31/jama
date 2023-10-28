//go:build linux && amd64

package jama

import "golang.org/x/sys/unix"

// Mutator provides a method for mutating registers.
type Mutator interface {
	// Mutate modifies regs.
	Mutate(regs *unix.PtraceRegs)
}

// noopMutator is a Mutator that makes no changes.
type noopMutator struct{}

// Mutate implements Mutator.
func (noopMutator) Mutate(regs *unix.PtraceRegs) {}

// mutatorProvider provides a method for fetching the Mutator for a given tid.
type mutatorProvider interface {
	// mutatorForTID returns the mutator for the given tid.
	mutatorForTID(tid int) Mutator
}

// globalMutatorProvider provides the same Mutator for all TIDs.
type globalMutatorProvider struct{ inner Mutator }

// mutatorForTID implements mutatorProvider.
func (mp globalMutatorProvider) mutatorForTID(tid int) Mutator {
	return mp.inner
}

// localMutatorProvider provides a different Mutator for each TID.
type localMutatorProvider map[int]Mutator

// mutatorForTID implements mutatorProvider.
func (mp localMutatorProvider) mutatorForTID(tid int) Mutator {
	m, ok := mp[tid]
	if !ok {
		return noopMutator{}
	}

	return m
}

// Ensure interfaces are satisfied.
var (
	_ Mutator         = noopMutator{}
	_ mutatorProvider = globalMutatorProvider{}
	_ mutatorProvider = localMutatorProvider{}
)
