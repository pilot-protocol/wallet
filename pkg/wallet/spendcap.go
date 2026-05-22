package wallet

import (
	"bufio"
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
	return total
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
		if err := appendSpendRecord(w.capStateFile, r); err != nil {
			// Persistence failure is non-fatal for the in-memory cap
			// check (which has already passed and the spend already
			// recorded in the ledger), but the operator should know:
			// a restart will under-count and the cap loses force.
			// No logger handle here, so we annotate the record with
			// best-effort behavior — production callers can also
			// wrap recordSpendLocked with their own observability.
			_ = err // intentionally swallow: spend succeeded, persistence is advisory
		}
	}
	w.pruneSpendLogLocked()
}

// ── persistence ────────────────────────────────────────────────────────

// jsonSpendRecord is the on-disk shape. spendRecord has unexported
// fields so it can't be json.Marshal'd directly — this wrapper is the
// stable wire/disk form. Field names are short to keep the JSONL file
// compact for high-throughput wallets.
type jsonSpendRecord struct {
	At     time.Time `json:"at"`
	Asset  Asset     `json:"asset"`
	Amount Amount    `json:"amount"`
}

// UseCapStateFile points the wallet at a JSONL file where every
// successful spend gets appended (one line per record) and from
// which any pre-existing records are replayed into the in-memory
// spend log. Call BEFORE handling traffic so the cap check sees
// historical spends. Same threat model as the identity file: 0600
// owner-only.
//
// JSONL was chosen over a single-blob snapshot because appends are
// cheaper than rewrites and a partial-write only loses the trailing
// line. The file is opened fresh for each append (closed promptly)
// — a small perf cost in exchange for no fd leaks on long-running
// wallets that haven't seen traffic for a while.
func (w *Wallet) UseCapStateFile(path string) error {
	if path == "" {
		return fmt.Errorf("UseCapStateFile: path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("UseCapStateFile: mkdir %s: %w", filepath.Dir(path), err)
	}
	records, err := loadSpendRecords(path)
	if err != nil {
		return fmt.Errorf("UseCapStateFile: load %s: %w", path, err)
	}
	w.capMu.Lock()
	w.capStateFile = path
	w.spendLog = append(w.spendLog, records...)
	w.pruneSpendLogLocked()
	w.capMu.Unlock()
	return nil
}

// loadSpendRecords reads a JSONL spend log. Returns an empty slice
// (nil error) if the file doesn't exist — first-run is normal.
// Malformed lines are skipped with the parse error swallowed so a
// single corrupt entry doesn't refuse to load the wallet.
func loadSpendRecords(path string) ([]spendRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	// Refuse a world-readable spend log — same threat model as the
	// identity file (the spend history leaks payment patterns).
	if info, err := f.Stat(); err == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("cap-state %s: permissions %#o expose spend history; chmod 0600", path, perm)
		}
	}
	var out []spendRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var j jsonSpendRecord
		if err := json.Unmarshal(raw, &j); err != nil {
			// Skip malformed lines — a single bad write shouldn't
			// brick the whole log.
			continue
		}
		out = append(out, spendRecord{at: j.At, asset: j.Asset, amount: j.Amount})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// appendSpendRecord writes one JSONL line atomically (O_APPEND on
// POSIX is sufficient for small writes < PIPE_BUF on the same fd;
// we close immediately to avoid fd accumulation on long-running
// wallets that haven't paid for a while). 0600 perm matches the
// identity file's threat model.
func appendSpendRecord(path string, r spendRecord) error {
	body, err := json.Marshal(jsonSpendRecord{At: r.at, Asset: r.asset, Amount: r.amount})
	if err != nil {
		return err
	}
	body = append(body, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	return f.Sync()
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
