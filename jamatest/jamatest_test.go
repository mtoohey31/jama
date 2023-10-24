package jamatest

import (
	"os"
	"sync"
	"testing"

	"mtoohey.com/jama"
)

// func TestMain(m *testing.M) {
// 	_ = runtime.GOOS
// 	_ = jama.Init

// 	// runtime.LockOSThread()
// 	// if err := unix.Kill(unix.Getpid(), unix.SIGSTOP); err != nil {
// 	// 	fmt.Fprintln(os.Stderr, err)
// 	// 	os.Exit(1)
// 	// }
// 	jama.Init()
// 	os.Exit(m.Run())
// }

func TestFoo(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := os.Stat("file")
		if err != nil {
			t.Fatal(err)
		}
	}()
	wg.Wait()
}

func TestBar(t *testing.T) {
	jama.WithLocal(nil, func() {
		_, err := os.Stat("file")
		if err != nil {
			t.Fatal(err)
		}
	})
}
