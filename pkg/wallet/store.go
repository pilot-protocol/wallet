package wallet

// Store is the wallet's persistence boundary. Two implementations ship in
// this package: memoryStore (volatile, for tests) and sqliteStore (WAL-
// backed file, for real runs). The Wallet holds no mutable state of its
// own — everything goes through Store, and Store is responsible for
// atomicity of the compound operations (RecordPay, RecordSettle,
// RecordTopup).
//
// Sentinel errors returned by RecordPay/RecordSettle are exported from
// wallet.go (ErrInsufficientBalance, ErrAlreadySettled, ErrUnknownChallenge);
// store implementations must return those exact values, not wrapped, so
// callers can `errors.Is` cleanly.
type Store interface {
	// Close releases the underlying resources. After Close the Store is
	// unusable; subsequent calls return an unspecified error.
	Close() error

	// Balance returns the current balance for an asset. Unknown asset → 0, nil.
	Balance(asset Asset) (Amount, error)

	// Balances returns a snapshot of all non-zero balances.
	Balances() (map[Asset]Amount, error)

	// SaveIssued persists a Challenge the local wallet just issued, so a
	// later Settle can confirm the challenge originated here.
	SaveIssued(ch *Challenge) error

	// GetIssued returns the issued Challenge for an ID, or nil if not
	// present. Used internally by Settle.
	GetIssued(id string) (*Challenge, error)

	// IsSettled reports whether a Challenge ID has already been settled.
	IsSettled(id string) (bool, error)

	// RecordPay atomically: checks balance ≥ tx.Amount, decrements balance,
	// appends the transaction to history. Returns ErrInsufficientBalance if
	// the balance would go negative; nothing is mutated on that error.
	RecordPay(tx Transaction) error

	// RecordSettle atomically: rejects with ErrAlreadySettled if chID is
	// already in the settled set; rejects with ErrUnknownChallenge if the
	// challenge isn't in issued; otherwise marks settled, deletes the
	// issued row, credits the balance, appends the transaction.
	RecordSettle(tx Transaction, chID string) error

	// RecordTopup atomically: credits balance + appends the transaction.
	RecordTopup(tx Transaction) error

	// History returns ledger entries newest-first, filtered as requested.
	History(f HistoryFilter) ([]Transaction, error)
}
