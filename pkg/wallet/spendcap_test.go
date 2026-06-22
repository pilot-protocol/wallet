package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// TestPayHonorsSpendCap drives the rolling-window enforcement: with a
// 100-unit/day cap, Pay-ing 60 + 60 in the same hour must refuse the
// second call; advancing the wallet's clock past the 24-hour window
// must let the next Pay through.
func TestPayHonorsSpendCap(t *testing.T) {
	s, _ := NewLocalSigner()
	bob := NewInMemory(addrBob, s)
	defer bob.Close()
	alice := NewInMemory(addrAlice, s)
	defer alice.Close()

	// Pluggable clock — start at a fixed instant so cap-window
	// arithmetic is deterministic.
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	bob.clock = func() time.Time { return now }
	alice.clock = func() time.Time { return now }

	bob.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})
	if _, err := bob.Topup("USDC", 1000, "dev:faucet"); err != nil {
		t.Fatalf("topup: %v", err)
	}

	// First Pay of 60 is inside the cap.
	ch1, err := alice.Request(60, "USDC", time.Hour, "first")
	if err != nil {
		t.Fatalf("request1: %v", err)
	}
	if _, err := bob.Pay(ch1); err != nil {
		t.Fatalf("first pay: %v", err)
	}

	// Second Pay of 60 would total 120/100 — must refuse.
	ch2, _ := alice.Request(60, "USDC", time.Hour, "second")
	_, err = bob.Pay(ch2)
	if err == nil {
		t.Fatal("second pay accepted, want ErrSpendCapExceeded")
	}
	if !errors.Is(err, ErrSpendCapExceeded) {
		t.Errorf("err %v, want ErrSpendCapExceeded", err)
	}
	for _, frag := range []string{"USDC", "used=60", "limit=100", "requested=60", "remaining=40"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q missing %q — should help the user see why", err.Error(), frag)
		}
	}

	// A Pay of exactly the remaining (40) lands.
	ch3, _ := alice.Request(40, "USDC", time.Hour, "third")
	if _, err := bob.Pay(ch3); err != nil {
		t.Fatalf("third pay (= remaining) refused: %v", err)
	}

	// Cap is now fully used. Any further Pay refuses.
	ch4, _ := alice.Request(1, "USDC", time.Hour, "fourth")
	if _, err := bob.Pay(ch4); !errors.Is(err, ErrSpendCapExceeded) {
		t.Errorf("fourth pay err %v, want ErrSpendCapExceeded", err)
	}

	// Advance the clock past the 24h window — the spend log entries
	// fall out of the rolling sum, so a fresh Pay lands.
	now = now.Add(25 * time.Hour)
	ch5, _ := alice.Request(70, "USDC", time.Hour, "fifth")
	if _, err := bob.Pay(ch5); err != nil {
		t.Fatalf("fifth pay (post-window) refused: %v", err)
	}
}

// TestSpendCapIgnoresDifferentAssets confirms caps are asset-scoped:
// a USDC cap doesn't restrict EUR payments and vice versa. Without
// this we'd silently sum spend across all assets and produce
// nonsense limits.
func TestSpendCapIgnoresDifferentAssets(t *testing.T) {
	s, _ := NewLocalSigner()
	bob := NewInMemory(addrBob, s)
	defer bob.Close()
	alice := NewInMemory(addrAlice, s)
	defer alice.Close()

	bob.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 10, Window: 24 * time.Hour})
	if _, err := bob.Topup("USDC", 100, "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Topup("EUR", 100, "dev"); err != nil {
		t.Fatal(err)
	}

	// 50 EUR — no cap on EUR → must pass.
	eur, _ := alice.Request(50, "EUR", time.Hour, "eur-pay")
	if _, err := bob.Pay(eur); err != nil {
		t.Errorf("EUR pay refused under USDC-only cap: %v", err)
	}

	// 5 USDC — inside USDC cap → must pass.
	usdc, _ := alice.Request(5, "USDC", time.Hour, "usdc-pay")
	if _, err := bob.Pay(usdc); err != nil {
		t.Errorf("USDC pay (under cap) refused: %v", err)
	}

	// 6 USDC — exceeds 10/24h cap (already spent 5).
	over, _ := alice.Request(6, "USDC", time.Hour, "usdc-over")
	if _, err := bob.Pay(over); !errors.Is(err, ErrSpendCapExceeded) {
		t.Errorf("USDC over-cap err %v, want ErrSpendCapExceeded", err)
	}
}

// TestParseSpendCapsFromManifest extracts caps from a synthetic manifest
// covering every supported `per` value plus all the "skip silently"
// edge cases. Mixed grant types must coexist (caps for key.sign +
// rate-limits for net.dial) without the cap parser tripping on the
// non-cap entries.
func TestParseSpendCapsFromManifest(t *testing.T) {
	grants := []manifest.Grant{
		{Cap: "fs.read", Target: "$APP/data.db"}, // not key.sign — ignored
		{Cap: "key.sign", Target: "x402-auth", // missing condition — ignored
		},
		{Cap: "key.sign", Target: "x402-auth", Condition: &manifest.Condition{
			Kind: "rate", // not "cap" — ignored
			Params: map[string]interface{}{
				"per":   "min",
				"limit": float64(100),
			},
		}},
		{Cap: "key.sign", Target: "x402-auth", Condition: &manifest.Condition{
			Kind: "cap",
			Params: map[string]interface{}{
				"asset": "USDC",
				"per":   "day",
				"limit": float64(1000),
			},
		}},
		{Cap: "key.sign", Target: "evm-eip3009", Condition: &manifest.Condition{
			Kind: "cap",
			Params: map[string]interface{}{
				"asset": "USDC",
				"per":   "hour",
				"limit": float64(500),
			},
		}},
		{Cap: "key.sign", Target: "garbage", Condition: &manifest.Condition{
			Kind: "cap",
			Params: map[string]interface{}{
				"asset": "USDC",
				"per":   "fortnight", // unknown — ignored
				"limit": float64(50),
			},
		}},
		{Cap: "key.sign", Target: "negative", Condition: &manifest.Condition{
			Kind: "cap",
			Params: map[string]interface{}{
				"asset": "USDC",
				"per":   "day",
				"limit": float64(-1), // refuse negative — ignored
			},
		}},
		{Cap: "key.sign", Target: "missing-asset", Condition: &manifest.Condition{
			Kind: "cap",
			Params: map[string]interface{}{
				"per":   "day",
				"limit": float64(100), // no asset — ignored
			},
		}},
	}
	caps := ParseSpendCapsFromManifest(grants)
	if len(caps) != 2 {
		t.Fatalf("got %d caps, want 2 — only the well-formed key.sign+cap entries should land", len(caps))
	}
	// Order should match traversal order so callers know what they
	// got without re-sorting; assert the well-formed entries by
	// (Asset, Window, Limit).
	if caps[0] != (SpendCap{Asset: "USDC", Limit: 1000, Window: 24 * time.Hour, Target: "x402-auth"}) {
		t.Errorf("caps[0]: %+v, want {USDC, 1000, 24h, x402-auth}", caps[0])
	}
	if caps[1] != (SpendCap{Asset: "USDC", Limit: 500, Window: time.Hour, Target: "evm-eip3009"}) {
		t.Errorf("caps[1]: %+v, want {USDC, 500, 1h, evm-eip3009}", caps[1])
	}
}

// TestParseSpendCapsFromManifestOnEmpty reports an empty grants block
// as nil, not panic-or-error, so callers can `w.SetSpendCaps(parsed...)`
// without nil-checking.
func TestParseSpendCapsFromManifestOnEmpty(t *testing.T) {
	if caps := ParseSpendCapsFromManifest(nil); caps != nil {
		t.Errorf("ParseSpendCapsFromManifest(nil) = %v, want nil", caps)
	}
	if caps := ParseSpendCapsFromManifest([]manifest.Grant{}); caps != nil {
		t.Errorf("ParseSpendCapsFromManifest([]) = %v, want nil", caps)
	}
}

// TestSpendCapsPersistAcrossRestart confirms the JSONL persistence
// path: spend half the cap, "restart" the wallet (close + new
// instance pointed at the same cap-state file), and the cap is
// still half-consumed. Without persistence a restart resets the
// counter to zero, which is a bypassable cap.
func TestSpendCapsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	capStatePath := filepath.Join(dir, "cap-state.jsonl")
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	// First wallet: configure cap=100, spend 60.
	{
		s, _ := NewLocalSigner()
		bob := NewInMemory(addrBob, s)
		alice := NewInMemory(addrAlice, s)
		bob.clock = func() time.Time { return now }
		alice.clock = func() time.Time { return now }
		if err := bob.UseCapStateFile(capStatePath); err != nil {
			t.Fatalf("UseCapStateFile: %v", err)
		}
		bob.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})
		if _, err := bob.Topup("USDC", 1000, "dev"); err != nil {
			t.Fatal(err)
		}
		ch, _ := alice.Request(60, "USDC", time.Hour, "first")
		if _, err := bob.Pay(ch); err != nil {
			t.Fatalf("first pay: %v", err)
		}
		bob.Close()
		alice.Close()
	}

	// Inspect persisted file — must contain exactly one record.
	raw, err := os.ReadFile(capStatePath)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if lines := strings.Count(string(raw), "\n"); lines != 1 {
		t.Errorf("persisted file has %d lines, want 1: %q", lines, raw)
	}

	// Second wallet: same cap state file, same caps. A 50-Pay would
	// total 110/100 → must refuse, proving the prior spend survived.
	s, _ := NewLocalSigner()
	bob := NewInMemory(addrBob, s)
	defer bob.Close()
	alice := NewInMemory(addrAlice, s)
	defer alice.Close()
	bob.clock = func() time.Time { return now.Add(time.Minute) } // inside window
	alice.clock = func() time.Time { return now.Add(time.Minute) }
	if err := bob.UseCapStateFile(capStatePath); err != nil {
		t.Fatalf("UseCapStateFile (restart): %v", err)
	}
	bob.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})
	if _, err := bob.Topup("USDC", 1000, "dev"); err != nil {
		t.Fatal(err)
	}

	// Confirm SpentInWindow remembers the prior 60.
	if got := bob.SpentInWindow("USDC", 24*time.Hour); got != 60 {
		t.Errorf("post-restart SpentInWindow = %d, want 60", got)
	}

	// A 50-Pay would put total at 110/100 — must refuse.
	ch, _ := alice.Request(50, "USDC", time.Hour, "would-exceed")
	_, err = bob.Pay(ch)
	if !errors.Is(err, ErrSpendCapExceeded) {
		t.Errorf("post-restart pay err %v, want ErrSpendCapExceeded — persistence didn't survive", err)
	}

	// A 40-Pay still fits (60 + 40 = exactly the limit).
	ch2, _ := alice.Request(40, "USDC", time.Hour, "fits")
	if _, err := bob.Pay(ch2); err != nil {
		t.Errorf("post-restart 40-pay (= remaining headroom) refused: %v", err)
	}
}

// TestSpendCapsPersistenceRefusesWorldReadable mirrors the
// identity-file check: a 0644 cap-state file leaks the wallet's
// payment history, so loading must refuse.
func TestSpendCapsPersistenceRefusesWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cap-state.jsonl")
	if err := os.WriteFile(path, []byte(`{"at":"2026-05-21T12:00:00Z","asset":"USDC","amount":1}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewLocalSigner()
	w := NewInMemory(addrBob, s)
	defer w.Close()
	err := w.UseCapStateFile(path)
	if err == nil {
		t.Fatal("UseCapStateFile accepted 0644 cap-state — should refuse")
	}
	if !strings.Contains(err.Error(), "permissions") {
		t.Errorf("err %q should mention permissions", err.Error())
	}
}

// TestSpendCapNoneConfigured ensures the default — no caps — preserves
// the pre-cap behavior. A regression here would silently block real
// wallets that haven't opted in.
func TestSpendCapNoneConfigured(t *testing.T) {
	s, _ := NewLocalSigner()
	bob := NewInMemory(addrBob, s)
	defer bob.Close()
	alice := NewInMemory(addrAlice, s)
	defer alice.Close()

	if _, err := bob.Topup("USDC", 1_000_000_000, "dev"); err != nil {
		t.Fatal(err)
	}
	// Several large pays in a row, no caps configured — never refuses.
	for i := 0; i < 5; i++ {
		ch, _ := alice.Request(50_000_000, "USDC", time.Hour, "no-cap")
		if _, err := bob.Pay(ch); err != nil {
			t.Fatalf("pay %d: %v (caps default to none)", i, err)
		}
	}
}

// testHMACKey returns a deterministic 32-byte key for cap-state tests.
func testHMACKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return k
}

// TestCapStateMalformedLineNotSilentlyDropped is the core fail-closed
// property: a garbage line in the cap-state file must NOT be silently
// skipped (the old behavior, which let an attacker erase a real spend
// by overwriting it with junk). Load must error so the wallet refuses
// to run against a corrupted/tampered log rather than under-counting.
func TestCapStateMalformedLineNotSilentlyDropped(t *testing.T) {
	t.Parallel()
	for _, key := range [][]byte{nil, testHMACKey()} {
		dir := t.TempDir()
		path := filepath.Join(dir, "cap-state.jsonl")
		content := `{"at":"2026-05-27T10:00:00Z","asset":"USDC","amount":5}
not-json garbage line
{"at":"2026-05-27T10:05:00Z","asset":"USDC","amount":7}
`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		recs, _, _, err := loadSpendRecords(path, key)
		if err == nil {
			t.Fatalf("key=%v: malformed line was silently accepted (got %d records, want error)", key != nil, len(recs))
		}
		if !strings.Contains(err.Error(), "malformed") {
			t.Errorf("key=%v: err %q should mention malformed", key != nil, err.Error())
		}
	}
}

// TestCapStateTamperedRecordDetected confirms that altering an
// authenticated record's amount (without recomputing its HMAC) is
// caught at load and fails closed.
func TestCapStateTamperedRecordDetected(t *testing.T) {
	t.Parallel()
	key := testHMACKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "cap-state.jsonl")

	// Write two authenticated records via the append path.
	r1 := spendRecord{at: mustTime("2026-05-27T10:00:00Z"), asset: "USDC", amount: 5}
	r2 := spendRecord{at: mustTime("2026-05-27T10:05:00Z"), asset: "USDC", amount: 7}
	tip, err := appendSpendRecord(path, r1, key, nil)
	if err != nil {
		t.Fatalf("append r1: %v", err)
	}
	if _, err := appendSpendRecord(path, r2, key, tip); err != nil {
		t.Fatalf("append r2: %v", err)
	}

	// Clean chain loads fine.
	if _, _, _, err := loadSpendRecords(path, key); err != nil {
		t.Fatalf("clean chain should load: %v", err)
	}

	// Tamper: bump the first record's amount but keep its old HMAC.
	raw, _ := os.ReadFile(path)
	tampered := strings.Replace(string(raw), `"amount":5`, `"amount":9999`, 1)
	if tampered == string(raw) {
		t.Fatal("tamper substitution did not apply")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	_, _, _, err = loadSpendRecords(path, key)
	if err == nil {
		t.Fatal("tampered record loaded without error — integrity check missing")
	}
	if !strings.Contains(err.Error(), "HMAC mismatch") {
		t.Errorf("err %q should mention HMAC mismatch", err.Error())
	}

	// A truncated chain (deleting the tail record) must also be caught
	// only if it breaks the chain; deleting the LAST record alone is
	// not detectable by a forward chain, but deleting/altering an
	// EARLIER record is — verify the mixed/append-plain tamper too.
	if err := os.WriteFile(path, append([]byte(nil), raw...), 0o600); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// Append an UNauthenticated record to a signed chain (attacker drops
	// in a plain record). The mixed-format guard must refuse.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.WriteString(`{"at":"2026-05-27T10:10:00Z","asset":"USDC","amount":1}` + "\n")
	_ = f.Close()
	if _, _, _, err := loadSpendRecords(path, key); err == nil {
		t.Fatal("signed chain + appended plain record loaded — mixed-format tamper not caught")
	}
}

// TestCapStateHMACRoundTrip confirms an authenticated chain written by
// the wallet survives a restart and the cap still holds — the secure
// analogue of TestSpendCapsPersistAcrossRestart.
func TestCapStateHMACRoundTrip(t *testing.T) {
	t.Parallel()
	key := testHMACKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "cap-state.jsonl")
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	{
		s, _ := NewLocalSigner()
		bob := NewInMemory(addrBob, s)
		alice := NewInMemory(addrAlice, s)
		bob.clock = func() time.Time { return now }
		alice.clock = func() time.Time { return now }
		if err := bob.UseCapStateFileWithHMAC(path, key); err != nil {
			t.Fatalf("UseCapStateFileWithHMAC: %v", err)
		}
		bob.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})
		bob.Topup("USDC", 1000, "dev")
		ch, _ := alice.Request(60, "USDC", time.Hour, "first")
		if _, err := bob.Pay(ch); err != nil {
			t.Fatalf("first pay: %v", err)
		}
		bob.Close()
		alice.Close()
	}

	// On-disk record must carry an HMAC field.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"hmac":`) {
		t.Fatalf("persisted record missing hmac field: %q", raw)
	}

	// Restart with the same key: prior spend survives + cap holds.
	s, _ := NewLocalSigner()
	bob := NewInMemory(addrBob, s)
	defer bob.Close()
	alice := NewInMemory(addrAlice, s)
	defer alice.Close()
	bob.clock = func() time.Time { return now.Add(time.Minute) }
	alice.clock = func() time.Time { return now.Add(time.Minute) }
	if err := bob.UseCapStateFileWithHMAC(path, key); err != nil {
		t.Fatalf("restart load: %v", err)
	}
	bob.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})
	bob.Topup("USDC", 1000, "dev")
	if got := bob.SpentInWindow("USDC", 24*time.Hour); got != 60 {
		t.Errorf("post-restart SpentInWindow = %d, want 60", got)
	}
	ch, _ := alice.Request(50, "USDC", time.Hour, "would-exceed")
	if _, err := bob.Pay(ch); !errors.Is(err, ErrSpendCapExceeded) {
		t.Errorf("post-restart 50-pay err %v, want ErrSpendCapExceeded", err)
	}
}

// TestCapStateLegacyMigration confirms a legacy (HMAC-less) file is
// migrated to an authenticated chain on first load with a key, after
// which a tamper is detectable.
func TestCapStateLegacyMigration(t *testing.T) {
	t.Parallel()
	key := testHMACKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "cap-state.jsonl")
	legacy := `{"at":"2026-05-27T10:00:00Z","asset":"USDC","amount":5}
{"at":"2026-05-27T10:05:00Z","asset":"USDC","amount":7}
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	recs, _, migrated, err := loadSpendRecords(path, key)
	if err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if !migrated {
		t.Fatal("all-legacy file should report migrated=true")
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	// Perform the migration as the wallet would, then verify the file
	// is now authenticated and tamper-evident.
	if _, err := rewriteSpendRecords(path, recs, key); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"hmac":`) {
		t.Fatalf("migrated file missing hmac: %q", raw)
	}
	// Re-load: now authenticated, no migration, clean.
	if _, _, m2, err := loadSpendRecords(path, key); err != nil || m2 {
		t.Fatalf("post-migration load err=%v migrated=%v", err, m2)
	}
	// Tamper now → caught.
	tampered := strings.Replace(string(raw), `"amount":5`, `"amount":1`, 1)
	os.WriteFile(path, []byte(tampered), 0o600)
	if _, _, _, err := loadSpendRecords(path, key); err == nil {
		t.Fatal("tamper after migration not detected")
	}
}

func mustTime(s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return tm
}
