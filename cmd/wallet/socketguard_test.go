package main

import (
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortSockDir returns a directory short enough for a unix socket path
// (macOS sun_path is 104 bytes; t.TempDir under /var/folders can exceed it).
func shortSockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "wsk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func listenOwned(t *testing.T, path string) *ownedUnixListener {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	return ownSocket(l.(*net.UnixListener), path, log.New(io.Discard, "", 0))
}

// An instance that shuts down after a replacement has taken over its
// socket path must not delete the replacement's socket.
func TestOwnedListenerCloseKeepsReplacementSocket(t *testing.T) {
	path := filepath.Join(shortSockDir(t), "app.sock")
	old := listenOwned(t, path)

	// The replacement does what the supervisor and the wallet's own
	// startup do: drop the stale socket file, then bind a fresh one.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	repl, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("replacement listen: %v", err)
	}
	defer repl.Close()

	if err := old.Close(); err != nil {
		t.Fatalf("old close: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("replacement's socket was removed by the old instance's Close: %v", err)
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := repl.Accept()
		if err == nil {
			c.Close()
		}
		accepted <- err
	}()
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial replacement: %v", err)
	}
	c.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("replacement accept: %v", err)
	}
}

// Normal shutdown still removes the wallet's own socket.
func TestOwnedListenerCloseUnlinksOwnSocket(t *testing.T) {
	path := filepath.Join(shortSockDir(t), "app.sock")
	l := listenOwned(t, path)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket still present after close (stat err=%v)", err)
	}
}

// If the socket file is already gone (someone removed it and nobody
// re-bound), Close must not fail or recreate anything.
func TestOwnedListenerCloseAfterExternalRemove(t *testing.T) {
	path := filepath.Join(shortSockDir(t), "app.sock")
	l := listenOwned(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("path reappeared (stat err=%v)", err)
	}
}
