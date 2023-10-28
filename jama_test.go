package jama

import (
	"errors"
	"math"
	"os"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
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
	Register[StatFailingMutator]()
	Init()
	os.Exit(m.Run())
}

func TestGlobal(t *testing.T) {
	WithGlobal(StatFailingMutator{}, func() {
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

func TestLocal(t *testing.T) {
	for i := 0; i < 5; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			WithLocal(StatFailingMutator{}, func() {
				_, err := os.Stat("file")
				if !errors.Is(err, unix.ENOENT) {
					t.Fatal("expected ENOENT, got:", err)
				}
			})
		})
	}
}
