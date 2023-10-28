package jamatest

import (
	"errors"
	"math"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"mtoohey.com/jama"
)

// StatFailingMutator is a jama.Mutator that causes os.Stat to fail.
type StatFailingMutator struct{}

// Mutate implements jama.Mutator.
func (StatFailingMutator) Mutate(regs *unix.PtraceRegs) {
	if regs.Orig_rax == unix.SYS_NEWFSTATAT {
		regs.Rax = uint64((unix.ENOENT ^ math.MaxUint64) + 1)
	}
}

func TestMain(m *testing.M) {
	jama.Register(StatFailingMutator{})
	jama.Init()
	os.Exit(m.Run())
}

func TestFoo(t *testing.T) {
	jama.WithGlobal(StatFailingMutator{}, func() {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := os.Stat("file")
			if !errors.Is(err, unix.ENOENT) {
				t.Fatal("expected ENOENT, got:", err)
			}
		}()
		wg.Wait()
	})
}

func TestBar(t *testing.T) {
	jama.WithLocal(StatFailingMutator{}, func() {
		_, err := os.Stat("file")
		if !errors.Is(err, unix.ENOENT) {
			t.Fatal("expected ENOENT, got:", err)
		}
	})
}
