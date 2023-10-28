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

func TestFoo(t *testing.T) {
	jama.WithGlobal(func(regs *unix.PtraceRegs) {
		if regs.Orig_rax == unix.SYS_NEWFSTATAT {
			regs.Rax = uint64((unix.ENOENT ^ math.MaxUint64) + 1)
		}
	}, func() {
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
	jama.WithLocal(func(regs *unix.PtraceRegs) {
		if regs.Orig_rax == unix.SYS_NEWFSTATAT {
			regs.Rax = uint64((unix.ENOENT ^ math.MaxUint64) + 1)
		}
	}, func() {
		_, err := os.Stat("file")
		if !errors.Is(err, unix.ENOENT) {
			t.Fatal("expected ENOENT, got:", err)
		}
	})
}
