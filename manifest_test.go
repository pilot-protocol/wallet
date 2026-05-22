// Package walletmod_test validates the wallet's shipped manifest.json
// against the canonical schema in app-store/pkg/manifest. Living at the
// module root rather than inside a sub-package so the test sees the
// manifest at its release-distributed location.
package walletmod_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
	"github.com/pilot-protocol/wallet/pkg/wallet"
	"github.com/pilot-protocol/wallet/pkg/walletipc"
)

// manifestPath locates manifest.json relative to this test file so it
// works regardless of where `go test` was invoked from.
func manifestPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "manifest.json")
}

func TestManifestParsesAndValidates(t *testing.T) {
	raw, err := os.ReadFile(manifestPath(t))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if errs := m.Validate(); len(errs) != 0 {
		for _, e := range errs {
			t.Errorf("validation: %v", e)
		}
	}
	if m.ID != "io.pilot.wallet" {
		t.Errorf("id: %q", m.ID)
	}
}

func TestManifestExposesAllIPCMethods(t *testing.T) {
	raw, _ := os.ReadFile(manifestPath(t))
	m, _ := manifest.Parse(raw)

	exposed := map[string]bool{}
	for _, e := range m.Exposes {
		exposed[e] = true
	}

	// All non-EVM IPC methods + all EVM IPC methods must be declared.
	for _, method := range append(append([]string{}, walletipc.AllMethods...), walletipc.AllEVMMethods...) {
		if !exposed[method] {
			t.Errorf("method %q not in manifest.exposes", method)
		}
	}
	// Hook callbacks must also be declared since they're called by name.
	for _, hook := range []string{"wallet.hookPreSendMessage", "wallet.hookPostRecvMessage"} {
		if !exposed[hook] {
			t.Errorf("hook %q not in manifest.exposes", hook)
		}
	}
}

func TestManifestExtendsBlockPresent(t *testing.T) {
	raw, _ := os.ReadFile(manifestPath(t))
	m, _ := manifest.Parse(raw)

	if len(m.Extends) < 2 {
		t.Fatalf("expected at least 2 extends entries, got %d", len(m.Extends))
	}

	// Find the send-message.pre entry; assert it has the --paywall flag.
	var sendPre *manifest.Extension
	for i := range m.Extends {
		if m.Extends[i].Primitive == "send-message.pre" {
			sendPre = &m.Extends[i]
			break
		}
	}
	if sendPre == nil {
		t.Fatal("missing send-message.pre in extends")
	}
	if sendPre.Method != "wallet.hookPreSendMessage" {
		t.Errorf("send-message.pre method: %q", sendPre.Method)
	}
	hasPaywall := false
	for _, f := range sendPre.AddsFlags {
		if f.Name == "--paywall" && f.Type == "string" {
			hasPaywall = true
			break
		}
	}
	if !hasPaywall {
		t.Errorf("send-message.pre missing --paywall flag: %+v", sendPre.AddsFlags)
	}
}

// TestWalletBinaryVersionMatchesManifest enforces that the static
// Version constant in cmd/wallet/main.go agrees with manifest.json's
// app_version. A bump to one without the other is the RC-release
// footgun this guards against.
func TestWalletBinaryVersionMatchesManifest(t *testing.T) {
	raw, _ := os.ReadFile(manifestPath(t))
	m, _ := manifest.Parse(raw)
	// Run the binary with --version and capture stdout. Uses `go run`
	// against the cmd/wallet source so the test doesn't need a
	// pre-built binary on disk.
	out, err := exec.Command("go", "run", "./cmd/wallet", "--version").Output()
	if err != nil {
		t.Fatalf("go run --version: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != m.AppVersion {
		t.Errorf("binary --version=%q, manifest app_version=%q — bump both together", got, m.AppVersion)
	}
}

func TestManifestVersionBumped(t *testing.T) {
	// The 2.0 schema introduces extends + new exposes. Per the
	// architecture's grant-drift rule, a manifest_version bump is
	// required so users re-consent to the changes.
	raw, _ := os.ReadFile(manifestPath(t))
	m, _ := manifest.Parse(raw)
	if m.ManifestVersion < 2 {
		t.Errorf("manifest_version: %d, want >= 2", m.ManifestVersion)
	}
}

func TestManifestDeclaresEIP3009Grant(t *testing.T) {
	raw, _ := os.ReadFile(manifestPath(t))
	m, _ := manifest.Parse(raw)
	found := false
	for _, g := range m.Grants {
		if g.Cap == "key.sign" && g.Target == "evm-eip3009" {
			found = true
			break
		}
	}
	if !found {
		t.Error("manifest lacks key.sign:evm-eip3009 grant")
	}
}

// TestShippedManifestSpendCapsParse round-trips the real wallet
// manifest through ParseSpendCapsFromManifest and asserts both
// declared caps come through. Without this, a manifest edit that
// breaks the grant schema would silently disable cap enforcement
// at the next install — a quiet regression we'd rather catch in CI.
func TestShippedManifestSpendCapsParse(t *testing.T) {
	raw, _ := os.ReadFile(manifestPath(t))
	m, _ := manifest.Parse(raw)
	caps := wallet.ParseSpendCapsFromManifest(m.Grants)
	if len(caps) != 2 {
		t.Fatalf("parsed %d caps from shipped manifest, want 2 (x402-auth + evm-eip3009)", len(caps))
	}
	// Both caps target USDC, both window=24h, both limit=100 (per manifest.json).
	for i, c := range caps {
		if c.Asset != "USDC" {
			t.Errorf("caps[%d].Asset = %q, want USDC", i, c.Asset)
		}
		if c.Window != 24*time.Hour {
			t.Errorf("caps[%d].Window = %s, want 24h", i, c.Window)
		}
		if c.Limit != 100 {
			t.Errorf("caps[%d].Limit = %d, want 100", i, c.Limit)
		}
	}
	// The two grants target different sign-purposes; without the
	// Target field carried through, multi-target manifests render as
	// indistinguishable duplicates in any introspection UI.
	targets := map[string]bool{}
	for _, c := range caps {
		targets[c.Target] = true
	}
	for _, want := range []string{"x402-auth", "evm-eip3009"} {
		if !targets[want] {
			t.Errorf("shipped manifest's caps missing target=%q (got targets=%v)", want, targets)
		}
	}
}
