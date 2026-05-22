package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/wallet/pkg/wallet"
	"github.com/pilot-protocol/wallet/pkg/walletipc"
)

// TestRunSmoke spins up the wallet binary in-process against a temp dir,
// connects to its unix socket, makes one wallet.address call, and asserts
// the wallet was wired correctly end-to-end. Also exercises clean
// shutdown via ctx cancel.
func TestRunSmoke(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "wallet.sock")
	db := filepath.Join(dir, "wallet.db")
	id := filepath.Join(dir, "identity.json")

	ctx, cancel := context.WithCancel(context.Background())

	errc := make(chan error, 1)
	go func() {
		errc <- run(ctx, []string{
			"--addr", "0:0001.0001.0001",
			"--db", db,
			"--socket", sock,
			"--identity", id,
		})
	}()

	// Wait for the socket to appear. Close the probe conn immediately so
	// it doesn't leak into the server's accept loop and block shutdown.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if probe, err := net.DialTimeout("unix", sock, 50*time.Millisecond); err == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-errc
			t.Fatalf("socket %s did not become reachable", sock)
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		cancel()
		<-errc
		t.Fatalf("dial: %v", err)
	}

	var addr walletipc.AddressResp
	if err := ipc.Call(conn, walletipc.MethodAddress, nil, &addr); err != nil {
		_ = conn.Close()
		cancel()
		<-errc
		t.Fatalf("address call: %v", err)
	}
	_ = conn.Close()
	if string(addr.Address) != "0:0001.0001.0001" {
		t.Errorf("address: %q, want %q", addr.Address, "0:0001.0001.0001")
	}

	// Trigger graceful shutdown.
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("run did not return after ctx cancel")
	}
}

// TestRunActivatesManifestSpendCaps spins up the wallet with --manifest
// pointed at a synthetic manifest declaring a USDC/day cap, then makes a
// wallet.pay call that exceeds the cap. Without this wiring the cap
// parser is dead code in production — the wallet binary is the only
// place a real user's manifest can ever activate caps.
func TestRunActivatesManifestSpendCaps(t *testing.T) {
	dir := t.TempDir()
	// macOS unix-socket path limit is 104 chars; t.TempDir under
	// /var/folders/... plus this test's name can blow past that.
	// Put the socket in a short directory and clean up afterwards.
	sockDir, err := os.MkdirTemp("", "wcap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "w.sock")
	db := filepath.Join(dir, "wallet.db")
	id := filepath.Join(dir, "identity.json")
	mfPath := filepath.Join(dir, "manifest.json")

	// Minimal manifest. ID/protection/etc are validated by manifest.Parse,
	// but the cap-extraction only cares about Grants[].Condition.
	mf := `{
		"id": "io.test.capwallet",
		"manifest_version": 1,
		"app_version": "0.0.1",
		"protection": "guarded",
		"binary": {"runtime": "go", "path": "bin/wallet", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"exposes": ["wallet.pay"],
		"grants": [
			{"cap": "key.sign", "target": "x402-auth",
			 "if": {"kind": "cap", "params": {"asset": "USDC", "per": "day", "limit": 10}}}
		]
	}`
	if err := os.WriteFile(mfPath, []byte(mf), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- run(ctx, []string{
			"--addr", "0:0001.0003.0003",
			"--db", db,
			"--socket", sock,
			"--identity", id,
			"--manifest", mfPath,
		})
	}()

	// Wait until the socket is up, OR run() returns early with an error.
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case runErr := <-errc:
			t.Fatalf("run() exited early: %v", runErr)
		default:
		}
		if probe, err := net.DialTimeout("unix", sock, 50*time.Millisecond); err == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-errc
			t.Fatalf("socket %s did not become reachable", sock)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() {
		cancel()
		<-errc
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Fund the wallet so the cap (10) — not insufficient balance — is what
	// kicks in on an over-the-limit pay.
	var topup walletipc.TopupResp
	if err := ipc.Call(conn, walletipc.MethodTopup, walletipc.TopupReq{
		Asset: "USDC", Amount: 100, Source: "dev",
	}, &topup); err != nil {
		t.Fatalf("topup: %v", err)
	}

	// Build a challenge issued by the same wallet (self-pay is fine for
	// the cap-trigger test; we just need an over-limit signed auth attempt).
	var req walletipc.RequestResp
	if err := ipc.Call(conn, walletipc.MethodRequest, walletipc.RequestReq{
		Amount:           20, // > cap (10)
		Asset:            "USDC",
		ExpiresInSeconds: 60,
		Memo:             "over-cap",
	}, &req); err != nil {
		t.Fatalf("request: %v", err)
	}

	// Pay should refuse — the manifest declared cap=10 and the request is 20.
	var pay walletipc.PayResp
	err = ipc.Call(conn, walletipc.MethodPay, walletipc.PayReq{Challenge: req.Challenge}, &pay)
	if err == nil {
		t.Fatal("Pay accepted over-cap amount, want cap-exceeded error")
	}
	// Server-side errors propagate as *ipc.ErrServerError; check the
	// message mentions the cap-exceeded sentinel so we know the
	// manifest → parser → SetSpendCaps wiring actually activated.
	var srv *ipc.ErrServerError
	if !errors.As(err, &srv) {
		t.Fatalf("err type %T (%v), want *ipc.ErrServerError", err, err)
	}
	if want := "spend cap exceeded"; !contains(srv.Msg, want) {
		t.Errorf("err message %q does not mention %q — caps may not be active", srv.Msg, want)
	}
	_ = wallet.ErrSpendCapExceeded // pin the import so the test stays meaningful
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestRunVersionFlag asserts the --version short-circuit: prints the
// binary's release tag and exits cleanly, no --addr required. Operators
// and packaging scripts depend on this; without it, the binary won't
// answer "what version am I?" at all.
func TestRunVersionFlag(t *testing.T) {
	if err := run(context.Background(), []string{"--version"}); err != nil {
		t.Errorf("--version returned err: %v (should exit cleanly)", err)
	}
}

// TestRunRequiresAddr asserts that --addr is mandatory.
func TestRunRequiresAddr(t *testing.T) {
	err := run(context.Background(), []string{
		"--db", filepath.Join(t.TempDir(), "x.db"),
		"--socket", filepath.Join(t.TempDir(), "x.sock"),
		"--identity", filepath.Join(t.TempDir(), "id.json"),
	})
	if err == nil {
		t.Fatal("expected error when --addr is missing")
	}
}
