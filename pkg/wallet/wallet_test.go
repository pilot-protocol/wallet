package wallet

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

const (
	addrAlice = "0:0001.0001.0001"
	addrBob   = "0:0001.0002.0002"
)

// storeFactory builds a fresh Store for one test. The returned cleanup
// must release any backing resources (file handles, temp dirs).
type storeFactory struct {
	name string
	make func(t *testing.T) Store
}

func allStoreFactories(t *testing.T) []storeFactory {
	t.Helper()
	return []storeFactory{
		{
			name: "memory",
			make: func(*testing.T) Store { return NewMemoryStore() },
		},
		{
			name: "sqlite",
			make: func(t *testing.T) Store {
				t.Helper()
				path := filepath.Join(t.TempDir(), "wallet.db")
				s, err := OpenSQLiteStore(path)
				if err != nil {
					t.Fatalf("open sqlite: %v", err)
				}
				t.Cleanup(func() { _ = s.Close() })
				return s
			},
		},
	}
}

func newWallet(t *testing.T, sf storeFactory, addr Address) *Wallet {
	t.Helper()
	s, err := NewLocalSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return New(addr, s, sf.make(t))
}

// TestWalletAllStores runs the full suite against every Store impl.
func TestWalletAllStores(t *testing.T) {
	for _, sf := range allStoreFactories(t) {
		sf := sf
		t.Run(sf.name, func(t *testing.T) {
			t.Run("TopupCreditsBalance", func(t *testing.T) { topupCreditsBalance(t, sf) })
			t.Run("RequestIssuesChallenge", func(t *testing.T) { requestIssuesChallenge(t, sf) })
			t.Run("EndToEndPayVerifySettle", func(t *testing.T) { endToEndPayVerifySettle(t, sf) })
			t.Run("PayInsufficientBalance", func(t *testing.T) { payInsufficientBalance(t, sf) })
			t.Run("PayExpiredChallenge", func(t *testing.T) { payExpiredChallenge(t, sf) })
			t.Run("VerifyRejectsTamperedAmount", func(t *testing.T) { verifyRejectsTamperedAmount(t, sf) })
			t.Run("VerifyRejectsForgedSignature", func(t *testing.T) { verifyRejectsForgedSignature(t, sf) })
			t.Run("VerifyRejectsWrongPubkey", func(t *testing.T) { verifyRejectsWrongPubkey(t, sf) })
			t.Run("SettleDoubleSpendBlocked", func(t *testing.T) { settleDoubleSpendBlocked(t, sf) })
			t.Run("SettleUnknownChallenge", func(t *testing.T) { settleUnknownChallenge(t, sf) })
			t.Run("HistoryFiltering", func(t *testing.T) { historyFiltering(t, sf) })
			t.Run("HistoryBeforeCursor", func(t *testing.T) { historyBeforeCursor(t, sf) })
			t.Run("BalancesSnapshot", func(t *testing.T) { balancesSnapshot(t, sf) })
		})
	}
}

func topupCreditsBalance(t *testing.T, sf storeFactory) {
	w := newWallet(t, sf, addrAlice)
	if got := w.Balance("USDC"); got != 0 {
		t.Fatalf("starting balance: %d, want 0", got)
	}
	tx, err := w.Topup("USDC", 500, "dev:faucet")
	if err != nil {
		t.Fatalf("topup: %v", err)
	}
	if tx.Kind != TxTopup || tx.Amount != 500 || tx.Asset != "USDC" || tx.Source != "dev:faucet" {
		t.Errorf("tx: %+v", tx)
	}
	if got := w.Balance("USDC"); got != 500 {
		t.Errorf("post-topup balance: %d, want 500", got)
	}
}

func requestIssuesChallenge(t *testing.T, sf storeFactory) {
	w := newWallet(t, sf, addrAlice)
	ch, err := w.Request(100, "USDC", time.Minute, "for coffee")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if ch.RecipientAddr != addrAlice || ch.Amount != 100 || ch.Asset != "USDC" || ch.Memo != "for coffee" {
		t.Errorf("challenge: %+v", ch)
	}
	if ch.ID == "" || ch.Nonce == "" {
		t.Errorf("missing id or nonce: %+v", ch)
	}
	if !ch.ExpiresAt.After(time.Now()) {
		t.Errorf("expiry should be future: %v", ch.ExpiresAt)
	}
}

func endToEndPayVerifySettle(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)

	if _, err := bob.Topup("USDC", 1000, "dev:faucet"); err != nil {
		t.Fatalf("bob topup: %v", err)
	}

	ch, err := alice.Request(250, "USDC", time.Minute, "lunch")
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	sa, err := bob.Pay(ch)
	if err != nil {
		t.Fatalf("pay: %v", err)
	}
	if bob.Balance("USDC") != 750 {
		t.Errorf("bob post-pay: %d, want 750", bob.Balance("USDC"))
	}

	tx, err := alice.Settle(ch, sa)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if tx.Kind != TxReceive || tx.Amount != 250 || tx.PeerAddr != addrBob {
		t.Errorf("settle tx: %+v", tx)
	}
	if alice.Balance("USDC") != 250 {
		t.Errorf("alice post-settle: %d, want 250", alice.Balance("USDC"))
	}
}

func payInsufficientBalance(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)

	ch, _ := alice.Request(100, "USDC", time.Minute, "")
	if _, err := bob.Pay(ch); !errors.Is(err, ErrInsufficientBalance) {
		t.Errorf("want ErrInsufficientBalance, got %v", err)
	}
	if bob.Balance("USDC") != 0 {
		t.Errorf("failed pay must not debit: %d", bob.Balance("USDC"))
	}
}

func payExpiredChallenge(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)
	_, _ = bob.Topup("USDC", 1000, "dev")

	ch, _ := alice.Request(100, "USDC", time.Millisecond, "")
	time.Sleep(10 * time.Millisecond)

	if _, err := bob.Pay(ch); !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("want ErrChallengeExpired, got %v", err)
	}
}

func verifyRejectsTamperedAmount(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)
	_, _ = bob.Topup("USDC", 1000, "dev")

	ch, _ := alice.Request(100, "USDC", time.Minute, "")
	sa, _ := bob.Pay(ch)

	sa.Amount = 9999
	if err := alice.Verify(ch, sa); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("want ErrChallengeMismatch, got %v", err)
	}
}

func verifyRejectsForgedSignature(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)
	_, _ = bob.Topup("USDC", 1000, "dev")

	ch, _ := alice.Request(100, "USDC", time.Minute, "")
	sa, _ := bob.Pay(ch)

	sa.Signature[0] ^= 0xFF
	if err := alice.Verify(ch, sa); !errors.Is(err, ErrBadSignature) {
		t.Errorf("want ErrBadSignature, got %v", err)
	}
}

func verifyRejectsWrongPubkey(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)
	_, _ = bob.Topup("USDC", 1000, "dev")

	ch, _ := alice.Request(100, "USDC", time.Minute, "")
	sa, _ := bob.Pay(ch)

	other, _ := NewLocalSigner()
	sa.PayerPubkey = other.PublicKey()
	if err := alice.Verify(ch, sa); !errors.Is(err, ErrBadSignature) {
		t.Errorf("want ErrBadSignature, got %v", err)
	}
}

func settleDoubleSpendBlocked(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)
	_, _ = bob.Topup("USDC", 1000, "dev")

	ch, _ := alice.Request(100, "USDC", time.Minute, "")
	sa, _ := bob.Pay(ch)

	if _, err := alice.Settle(ch, sa); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	if _, err := alice.Settle(ch, sa); !errors.Is(err, ErrAlreadySettled) {
		t.Errorf("want ErrAlreadySettled on replay, got %v", err)
	}
	if alice.Balance("USDC") != 100 {
		t.Errorf("balance must not double-credit: %d", alice.Balance("USDC"))
	}
}

func settleUnknownChallenge(t *testing.T, sf storeFactory) {
	alice := newWallet(t, sf, addrAlice)
	bob := newWallet(t, sf, addrBob)
	_, _ = bob.Topup("USDC", 1000, "dev")

	forged := &Challenge{
		ID:            "forged-id",
		RecipientAddr: addrAlice,
		Amount:        100,
		Asset:         "USDC",
		Nonce:         "deadbeef",
		ExpiresAt:     time.Now().Add(time.Minute),
	}
	sa, _ := bob.Pay(forged)

	if _, err := alice.Settle(forged, sa); !errors.Is(err, ErrUnknownChallenge) {
		t.Errorf("want ErrUnknownChallenge, got %v", err)
	}
}

func historyFiltering(t *testing.T, sf storeFactory) {
	w := newWallet(t, sf, addrAlice)
	_, _ = w.Topup("USDC", 100, "dev")
	_, _ = w.Topup("EUR", 50, "dev")
	_, _ = w.Topup("USDC", 25, "dev")

	all := w.History(HistoryFilter{})
	if len(all) != 3 {
		t.Fatalf("all: %d, want 3", len(all))
	}
	usdc := w.History(HistoryFilter{Asset: "USDC"})
	if len(usdc) != 2 {
		t.Errorf("USDC only: %d, want 2", len(usdc))
	}
	limited := w.History(HistoryFilter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("limit=1: %d, want 1", len(limited))
	}
}

// historyBeforeCursor verifies the Before-cursor pagination semantics:
// a caller pages newest→older by passing the oldest tx's timestamp
// from the prior page as Before on the next call.
func historyBeforeCursor(t *testing.T, sf storeFactory) {
	w := newWallet(t, sf, addrAlice)
	// Five topups, each at least one tick apart so newest-first sort is
	// deterministic (memory store uses the wallet clock, sqlite truncates
	// to UnixNano — both give distinct timestamps for sub-microsecond gaps).
	for i := 0; i < 5; i++ {
		if _, err := w.Topup("USDC", Amount(10+i), "dev"); err != nil {
			t.Fatalf("topup %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}

	page1 := w.History(HistoryFilter{Limit: 2})
	if len(page1) != 2 {
		t.Fatalf("page1: %d, want 2", len(page1))
	}
	page2 := w.History(HistoryFilter{Limit: 2, Before: page1[1].Timestamp})
	if len(page2) != 2 {
		t.Fatalf("page2: %d, want 2", len(page2))
	}
	page3 := w.History(HistoryFilter{Limit: 2, Before: page2[1].Timestamp})
	if len(page3) != 1 {
		t.Fatalf("page3: %d, want 1 (last one)", len(page3))
	}

	// All five distinct, in strict newest-first order.
	seen := map[string]bool{}
	last := page1[0].Timestamp
	for _, p := range [][]Transaction{page1, page2, page3} {
		for _, tx := range p {
			if seen[tx.ID] {
				t.Errorf("duplicate tx id %q across pages", tx.ID)
			}
			seen[tx.ID] = true
			if tx.Timestamp.After(last) {
				t.Errorf("pagination order broke: %v after %v", tx.Timestamp, last)
			}
			last = tx.Timestamp
		}
	}
	if len(seen) != 5 {
		t.Errorf("paged through %d unique txs, want 5", len(seen))
	}
}

func balancesSnapshot(t *testing.T, sf storeFactory) {
	w := newWallet(t, sf, addrAlice)
	_, _ = w.Topup("USDC", 100, "dev")
	_, _ = w.Topup("EUR", 50, "dev")

	bs := w.Balances()
	if bs["USDC"] != 100 || bs["EUR"] != 50 || len(bs) != 2 {
		t.Errorf("balances: %+v", bs)
	}
}

// TestSQLitePersistence is a sqlite-specific test that the in-memory store
// can't possibly cover: write, close, reopen, read.
func TestSQLitePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet.db")

	{
		s, err := OpenSQLiteStore(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		signer, _ := NewLocalSigner()
		w := New(addrAlice, signer, s)
		if _, err := w.Topup("USDC", 500, "dev"); err != nil {
			t.Fatalf("topup: %v", err)
		}
		ch, _ := w.Request(75, "EUR", time.Hour, "saved")
		if ch == nil {
			t.Fatal("nil challenge")
		}
		_ = w.Close()
	}

	s, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	signer, _ := NewLocalSigner()
	w := New(addrAlice, signer, s)

	if got := w.Balance("USDC"); got != 500 {
		t.Errorf("balance survived restart: got %d, want 500", got)
	}
	if h := w.History(HistoryFilter{}); len(h) != 1 || h[0].Kind != TxTopup {
		t.Errorf("history survived restart: %+v", h)
	}
}
