package main

import (
	"context"
	"io"
	"log"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchParentCancelsWhenReparented(t *testing.T) {
	var ppid atomic.Int64
	ppid.Store(4242)
	orig := getppid
	getppid = func() int { return int(ppid.Load()) }
	t.Cleanup(func() { getppid = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !watchParent(ctx, cancel, 4242, 5*time.Millisecond, log.New(io.Discard, "", 0)) {
		t.Fatal("watchParent refused a real parent pid")
	}

	select {
	case <-ctx.Done():
		t.Fatal("canceled while the parent was still alive")
	case <-time.After(50 * time.Millisecond):
	}

	ppid.Store(1) // parent died, reparented to init/launchd
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("ctx not canceled after the parent exited")
	}
}

func TestWatchParentSkipsInitParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, p := range []int{0, 1} {
		if watchParent(ctx, cancel, p, time.Millisecond, log.New(io.Discard, "", 0)) {
			t.Fatalf("watchParent(ppid=%d) armed; a wallet started by init has no parent to follow", p)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("ctx canceled")
	}
}
