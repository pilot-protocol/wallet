package main

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenConns_ReturnsSentinel(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	if got := openConns(&wg); got != -1 {
		t.Errorf("openConns = %d, want -1", got)
	}
}

func TestOpenStore_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.db")
	store, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
}

func TestOpenStore_MkdirFails(t *testing.T) {
	t.Parallel()
	// Under /dev/null the parent mkdir fails.
	if _, err := openStore("/dev/null/cannot/x/db.sqlite"); err == nil {
		t.Error("expected mkdir error")
	}
}

func TestDefaultPath_IncludesAppsRoot(t *testing.T) {
	t.Parallel()
	got := defaultPath("test-wallet")
	if !strings.Contains(got, "io.pilot.wallet") {
		t.Errorf("path = %q, want io.pilot.wallet substring", got)
	}
	if !strings.HasSuffix(got, "test-wallet") {
		t.Errorf("path = %q, want suffix test-wallet", got)
	}
}
