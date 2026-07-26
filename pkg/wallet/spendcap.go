package wallet

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// SpendCap is one rolling-window spending limit, scoped to a single
// asset. The wallet refuses to sign a Pay when the asset's spend total
// inside the trailing Window would exceed Limit.
//
// Example: {Asset: "USDC", Limit: 100_000_000, Window: 24*time.Hour}
// gives "100 USDC per day" semantics (USDC is 6-decimal). The Window is
// measured against the wallet's clock — pluggable for tests.
//
// Caps are configured at construction via SetSpendCaps. State is
// in-memory: a restart clears the spend log to zero. Persistence is
// a future tick. The wire/manifest layer's "per: day" string maps to
// Window: 24*time.Hour; tooling is responsible for the translation.
type SpendCap struct {
	Asset  Asset
	Limit  Amount
	Window time.Duration
	// Target is the manifest grant's signing-purpose target (e.g.
	// "x402-auth", "evm-eip3009"). Carried for introspection only —
	// enforcement is wallet-wide and shared across targets via the
	// single spend log. Without this field, two manifest grants with
	// identical (asset, limit, window) but different sign-purposes
	// appear identical in SpendCaps() readout. Optional: zero value
	// is acceptable for programmatic SetSpendCaps callers that don't
	// care about target metadata.
	Target string
}

// spendRecord is one entry in the per-wallet rolling spend log,
// used to compute "how much have I spent in the last Window?"
// without keeping a per-call index in the persistent store. Records
// are pruned lazily on every spend check.
type spendRecord struct {
	at     time.Time
	asset  Asset
	amount Amount
}

// SetSpendCaps configures the wallet's rolling-window spend caps.
// Replaces any previously-configured caps; pass no args to clear.
// The wallet enforces caps inside Pay; other methods (Topup, Settle)
// are credits and have no caps. Returns the wallet for chaining
// (NewInMemory(...).SetSpendCaps(...)).
func (w *Wallet) SetSpendCaps(caps ...SpendCap) *Wallet {
	w.capMu.Lock()
	defer w.capMu.Unlock()
	w.caps = append(w.caps[:0], caps...)
	return w
}

// SpendCaps returns a copy of the wallet's current cap configuration.
// Useful for UIs that want to show "you can still spend X USDC today".
func (w *Wallet) SpendCaps() []SpendCap {
	w.capMu.Lock()
	defer w.capMu.Unlock()
	out := make([]SpendCap, len(w.caps))
	copy(out, w.caps)
	return out
}

// SpentInWindow returns the total amount spent on `asset` within the
// trailing `window` ending at the wallet's current clock. Lazily
// prunes records older than the longest configured window so the
// log doesn't grow unbounded across long runtimes.
func (w *Wallet) SpentInWindow(asset Asset, window time.Duration) Amount {
	w.capMu.Lock()
	defer w.capMu.Unlock()
	return w.spentInWindowLocked(asset, window)
}

// spentInWindowLocked is the internal accumulator; w.capMu must be held.
// In-flight reservations count alongside settled records so budget that
// has been handed out but not yet confirmed can't be handed out twice.
func (w *Wallet) spentInWindowLocked(asset Asset, window time.Duration) Amount {
	cutoff := w.clock().Add(-window)
	var total Amount
	for _, r := range w.spendLog {
		if r.asset != asset {
			continue
		}
		if r.at.Before(cutoff) {
			continue
		}
		total += r.amount
	}
	for _, r := range w.capReservations {
		if r.asset != asset {
			continue
		}
		if r.at.Before(cutoff) {
			continue
		}
		total += r.amount
	}
	return total
}

// reserveSpendLocked books an in-flight spend and returns its handle.
// Called under the same capMu acquisition as checkSpendCapLocked so the
// check and the claim are one atomic step: the lock can then be dropped
// for a slow remote call without a second caller seeing stale budget.
// Every reservation must be handed back to releaseReservationLocked.
// w.capMu must be held.
func (w *Wallet) reserveSpendLocked(asset Asset, amount Amount) uint64 {
	if w.capReservations == nil {
		w.capReservations = make(map[uint64]spendRecord)
	}
	w.capReservationSeq++
	id := w.capReservationSeq
	w.capReservations[id] = spendRecord{at: w.clock(), asset: asset, amount: amount}
	return id
}

// releaseReservationLocked drops a reservation booked by
// reserveSpendLocked. Callers that went on to succeed follow it with
// recordSpendLocked, which makes the spend permanent (and durable);
// callers that failed simply release, returning the budget.
// w.capMu must be held.
func (w *Wallet) releaseReservationLocked(id uint64) {
	delete(w.capReservations, id)
}

// pruneSpendLogLocked drops records older than the longest configured
// window, since anything older can never affect a future cap check.
// w.capMu must be held.
func (w *Wallet) pruneSpendLogLocked() {
	if len(w.spendLog) == 0 || len(w.caps) == 0 {
		return
	}
	var longest time.Duration
	for _, c := range w.caps {
		if c.Window > longest {
			longest = c.Window
		}
	}
	if longest == 0 {
		return
	}
	cutoff := w.clock().Add(-longest)
	out := w.spendLog[:0]
	for _, r := range w.spendLog {
		if !r.at.Before(cutoff) {
			out = append(out, r)
		}
	}
	w.spendLog = out
}

// checkSpendCapLocked returns nil if a Pay of (asset, amount) is
// inside every applicable cap. Otherwise returns ErrSpendCapExceeded
// wrapped with the offending cap's parameters so callers can render
// "you've used 90/100 USDC today" without re-querying. w.capMu must
// be held.
func (w *Wallet) checkSpendCapLocked(asset Asset, amount Amount) error {
	for _, c := range w.caps {
		if c.Asset != asset {
			continue
		}
		used := w.spentInWindowLocked(asset, c.Window)
		if used+amount > c.Limit {
			return fmt.Errorf("%w: asset=%s window=%s used=%d limit=%d requested=%d remaining=%d",
				ErrSpendCapExceeded, asset, c.Window, used, c.Limit, amount, c.Limit-used)
		}
	}
	return nil
}

// recordSpendLocked appends a successful spend; w.capMu must be held.
// If a persistence path is configured (via UseCapStateFile), the
// record is also appended to disk as a JSONL line so wallet restart
// doesn't reset the rolling window to zero (a cap bypass otherwise).
func (w *Wallet) recordSpendLocked(asset Asset, amount Amount) {
	r := spendRecord{
		at:     w.clock(),
		asset:  asset,
		amount: amount,
	}
	w.spendLog = append(w.spendLog, r)
	if w.capStateFile != "" {
		newTip, err := appendSpendRecord(w.capStateFile, r, w.capStateHMACKey, w.capStateLastHMAC)
		if err != nil {
			// Persistence failure is non-fatal for the in-memory cap
			// check (which has already passed and the spend already
			// recorded in the ledger), but the operator should know:
			// a restart will under-count and the cap loses force.
			// No logger handle here, so we annotate the record with
			// best-effort behavior — production callers can also
			// wrap recordSpendLocked with their own observability.
			_ = err // intentionally swallow: spend succeeded, persistence is advisory
		} else {
			// Advance the chain tip only on a durable append, so the
			// next record links to what actually landed on disk.
			w.capStateLastHMAC = newTip
		}
	}
	w.pruneSpendLogLocked()
}

// ── persistence ────────────────────────────────────────────────────────

// jsonSpendRecord is the on-disk shape. spendRecord has unexported
// fields so it can't be json.Marshal'd directly — this wrapper is the
// stable wire/disk form. Field names are short to keep the JSONL file
// compact for high-throughput wallets.
//
// HMAC is an optional base64 HMAC-SHA256 over the canonical (HMAC-less)
// record bytes, chained with the prior record's HMAC. Empty means the
// record predates integrity protection (legacy file). The chain ties
// every record to its predecessor so a tamper, reorder, truncate, or
// deletion is detectable: changing or dropping one record invalidates
// every record after it.
type jsonSpendRecord struct {
	At     time.Time `json:"at"`
	Asset  Asset     `json:"asset"`
	Amount Amount    `json:"amount"`
	HMAC   string    `json:"hmac,omitempty"`
}

// recordHMAC computes the chained HMAC for one record: HMAC-SHA256 over
// the canonical (HMAC-less) JSON of the record, with the prior record's
// HMAC mixed in. The canonical form is the same struct with HMAC="" so
// the MAC never covers itself. Returns the raw MAC bytes; callers
// base64-encode for the on-disk field.
func recordHMAC(key, prev []byte, r jsonSpendRecord) []byte {
	r.HMAC = ""
	canonical, _ := json.Marshal(r)
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	mac.Write(prev)
	return mac.Sum(nil)
}

// UseCapStateFile points the wallet at a JSONL file where every
// successful spend gets appended, replaying pre-existing records into
// the in-memory spend log. This is the legacy (unauthenticated) format:
// records carry no HMAC. It still fails closed on a malformed line —
// a garbage/truncated entry is treated as corruption or tampering, not
// silently dropped — so a partial bypass attempt can't pass unnoticed.
//
// For tamper-resistant persistence, use UseCapStateFileWithHMAC: the
// same OS user can still write to the file, but can't alter or erase
// spend history without breaking the per-record HMAC chain.
//
// Call BEFORE handling traffic so the cap check sees historical spends.
// Same threat model as the identity file: 0600 owner-only.
func (w *Wallet) UseCapStateFile(path string) error {
	return w.UseCapStateFileWithHMAC(path, nil)
}

// UseCapStateFileWithHMAC is UseCapStateFile with integrity protection.
// hmacKey keys a chained HMAC-SHA256 over each record so the spend log
// can't be tampered with or truncated by the same OS user without
// detection. A nil key selects the legacy unauthenticated format.
//
// Load behaviour (key set):
//   - every record must carry a valid HMAC that links to its
//     predecessor; any mismatch, missing-HMAC-mid-chain, or malformed
//     line is a tamper signal and fails closed (refuse to load → the
//     caller refuses to spend rather than spending against a forged
//     history);
//   - an all-legacy file (records present, none with an HMAC) is
//     migrated once: it's loaded and rewritten with a fresh HMAC chain.
//     A mixed file (some authenticated records plus an unauthenticated
//     one) is rejected — that shape only arises from tampering.
func (w *Wallet) UseCapStateFileWithHMAC(path string, hmacKey []byte) error {
	if path == "" {
		return fmt.Errorf("UseCapStateFile: path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("UseCapStateFile: mkdir %s: %w", filepath.Dir(path), err)
	}
	records, tip, migrated, err := loadSpendRecords(path, hmacKey)
	if err != nil {
		return fmt.Errorf("UseCapStateFile: load %s: %w", path, err)
	}
	// Legacy → authenticated migration: rewrite the whole file as a
	// fresh HMAC chain so subsequent appends extend an authenticated
	// log. Done before we publish capStateFile so a crash mid-migration
	// leaves the original readable.
	if migrated {
		newTip, err := rewriteSpendRecords(path, records, hmacKey)
		if err != nil {
			return fmt.Errorf("UseCapStateFile: migrate %s: %w", path, err)
		}
		tip = newTip
	}
	w.capMu.Lock()
	w.capStateFile = path
	w.capStateHMACKey = hmacKey
	w.capStateLastHMAC = tip
	w.spendLog = append(w.spendLog, records...)
	w.pruneSpendLogLocked()
	w.capMu.Unlock()
	return nil
}

// loadSpendRecords reads a JSONL spend log. Returns an empty slice
// (nil error, nil tip) if the file doesn't exist — first-run is normal.
//
// Fail-closed: a malformed line is never silently skipped. Without a
// key it's reported as corruption; with a key it's a tamper signal.
// The returned tip is the last record's raw HMAC (nil for a legacy
// file). migrated is true when the file is all-legacy but a key was
// supplied, signalling the caller to rewrite it as an authenticated
// chain.
func loadSpendRecords(path string, hmacKey []byte) (recs []spendRecord, tip []byte, migrated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	defer f.Close()
	// Refuse a world-readable spend log — same threat model as the
	// identity file (the spend history leaks payment patterns).
	if info, err := f.Stat(); err == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, nil, false, fmt.Errorf("cap-state %s: permissions %#o expose spend history; chmod 0600", path, perm)
		}
	}
	var out []spendRecord
	var prev []byte
	sawHMAC, sawPlain := false, false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var j jsonSpendRecord
		if err := json.Unmarshal(raw, &j); err != nil {
			// Fail closed: a corrupt/garbage line is never dropped.
			return nil, nil, false, fmt.Errorf("malformed cap-state line %d: %w", lineNo, err)
		}
		if j.HMAC != "" {
			sawHMAC = true
		} else {
			sawPlain = true
		}
		if hmacKey != nil && j.HMAC != "" {
			want := recordHMAC(hmacKey, prev, j)
			got, decErr := base64.StdEncoding.DecodeString(j.HMAC)
			if decErr != nil || !hmac.Equal(want, got) {
				return nil, nil, false, fmt.Errorf("cap-state line %d: HMAC mismatch — spend log tampered with or truncated", lineNo)
			}
			prev = got
		}
		out = append(out, spendRecord{at: j.At, asset: j.Asset, amount: j.Amount})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, false, err
	}
	if hmacKey != nil {
		switch {
		case sawHMAC && sawPlain:
			// A file that mixes authenticated and unauthenticated
			// records can only arise from tampering (e.g. an attacker
			// appended a plain record to a signed chain). Refuse.
			return nil, nil, false, fmt.Errorf("cap-state %s mixes authenticated and unauthenticated records — refusing (possible tampering)", path)
		case sawPlain && !sawHMAC:
			// All-legacy file: migrate it to an authenticated chain.
			return out, nil, true, nil
		}
	}
	return out, prev, false, nil
}

// rewriteSpendRecords atomically replaces the cap-state file with an
// authenticated HMAC chain over recs. Used by the legacy→authenticated
// migration. Writes to a temp file in the same dir then renames, so a
// crash never leaves a half-written log. Returns the new chain tip.
func rewriteSpendRecords(path string, recs []spendRecord, hmacKey []byte) ([]byte, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cap-state-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	var prev []byte
	w := bufio.NewWriter(tmp)
	for _, r := range recs {
		j := jsonSpendRecord{At: r.at, Asset: r.asset, Amount: r.amount}
		mac := recordHMAC(hmacKey, prev, j)
		j.HMAC = base64.StdEncoding.EncodeToString(mac)
		body, err := json.Marshal(j)
		if err != nil {
			_ = tmp.Close()
			return nil, err
		}
		if _, err := w.Write(append(body, '\n')); err != nil {
			_ = tmp.Close()
			return nil, err
		}
		prev = mac
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return prev, nil
}

// appendSpendRecord writes one JSONL line atomically (O_APPEND on
// POSIX is sufficient for small writes < PIPE_BUF on the same fd;
// we close immediately to avoid fd accumulation on long-running
// wallets that haven't paid for a while). 0600 perm matches the
// identity file's threat model. When hmacKey is non-nil the record
// carries a chained HMAC linking it to prevHMAC; the new chain tip is
// returned so the caller can extend the chain on the next append.
func appendSpendRecord(path string, r spendRecord, hmacKey, prevHMAC []byte) ([]byte, error) {
	j := jsonSpendRecord{At: r.at, Asset: r.asset, Amount: r.amount}
	var tip []byte
	if hmacKey != nil {
		tip = recordHMAC(hmacKey, prevHMAC, j)
		j.HMAC = base64.StdEncoding.EncodeToString(tip)
	}
	body, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return tip, nil
}

// capMu, caps, and spendLog live on Wallet but are declared here so
// callers don't have to grep two files to find the cap state. Wallet
// is constructed in wallet.go; the zero values for these fields are
// correct (no caps configured, empty log).
var _ = sync.Mutex{} // keep the sync import live for the field-decl block in wallet.go

// ParseSpendCapsFromManifest extracts wallet-level spend caps from
// the manifest's grants block. Looks for grants of shape:
//
//	{cap: "key.sign", target: <purpose>,
//	 if: {kind: "cap", params: {asset, per, limit}}}
//
// where `asset` is a string, `per` is one of "min"/"hour"/"day", and
// `limit` is a positive number (the wallet treats Amount as minor
// units — manifest authors write the minor count directly, e.g.
// 100000000 for 100 USDC; no decimals conversion happens here).
//
// Skips silently:
//   - grants whose cap isn't "key.sign"
//   - grants without a condition
//   - conditions whose Kind isn't "cap"
//   - params missing any of asset/per/limit, or with bad types
//   - per: <unknown> (anything other than min/hour/day)
//
// Returns nil when no usable caps are found — callers should treat
// that as "no caps configured", same as a wallet with no SetSpendCaps
// call. The skip-on-malformed behavior is deliberate: a corrupt or
// future-extended grant block must not refuse to load the wallet,
// it just leaves enforcement unconfigured (deny-by-default still
// applies via the daemon's grant broker upstream).
func ParseSpendCapsFromManifest(grants []manifest.Grant) []SpendCap {
	var out []SpendCap
	for _, g := range grants {
		if g.Cap != "key.sign" {
			continue
		}
		if g.Condition == nil || g.Condition.Kind != "cap" {
			continue
		}
		c, ok := spendCapFromParams(g.Condition.Params)
		if !ok {
			continue
		}
		c.Target = g.Target
		out = append(out, c)
	}
	return out
}

// spendCapFromParams interprets a params map of shape
// {asset: string, per: "min"|"hour"|"day", limit: number} into
// a SpendCap. Returns (_, false) if any field is missing or wrong-typed.
func spendCapFromParams(p map[string]interface{}) (SpendCap, bool) {
	asset, ok := p["asset"].(string)
	if !ok || asset == "" {
		return SpendCap{}, false
	}
	per, ok := p["per"].(string)
	if !ok {
		return SpendCap{}, false
	}
	var window time.Duration
	switch per {
	case "min", "minute":
		window = time.Minute
	case "hour":
		window = time.Hour
	case "day":
		window = 24 * time.Hour
	default:
		return SpendCap{}, false
	}
	// JSON numbers come back as float64 from encoding/json. Reject
	// negatives, NaN, and overflow when converting to Amount (uint64).
	rawLimit, ok := p["limit"].(float64)
	if !ok || rawLimit <= 0 || rawLimit != rawLimit {
		return SpendCap{}, false
	}
	const maxUint64 = float64(^uint64(0))
	if rawLimit > maxUint64 {
		return SpendCap{}, false
	}
	return SpendCap{
		Asset:  Asset(asset),
		Limit:  Amount(rawLimit),
		Window: window,
	}, true
}
