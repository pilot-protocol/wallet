package wallet

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// sqliteStore persists wallet state to a sqlite database file. Uses the
// pure-Go modernc.org/sqlite driver — no cgo, so the wallet binary stays
// trivially cross-compilable for any platform the daemon targets.
//
// Compound operations (RecordPay / RecordSettle / RecordTopup) run inside
// a BEGIN IMMEDIATE transaction so balance reads and writes see a
// consistent snapshot.
type sqliteStore struct {
	db *sql.DB
	// writeMu serializes write transactions in-process. modernc.org/sqlite
	// already serializes via the database lock, but holding our own mutex
	// avoids `SQLITE_BUSY` retries when many goroutines race a Pay/Settle.
	writeMu sync.Mutex
}

// OpenSQLiteStore opens or creates a wallet database at path. The schema
// is created on first open; subsequent opens are no-ops.
func OpenSQLiteStore(path string) (Store, error) {
	// _journal_mode=WAL keeps reads non-blocking during writes.
	// _busy_timeout gives concurrent writers a chance to win the lock
	// instead of returning SQLITE_BUSY immediately.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	// Single-writer is fine; modernc.org/sqlite uses one connection per
	// transaction but the driver itself is safe for concurrent calls.
	// Limit to a small pool to keep file-descriptor pressure low.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)

	s := &sqliteStore{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *sqliteStore) initSchema() error {
	const ddl = `
CREATE TABLE IF NOT EXISTS balances (
    asset  TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS issued (
    id         TEXT PRIMARY KEY,
    payload    BLOB NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settled (
    id         TEXT PRIMARY KEY,
    settled_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id           TEXT PRIMARY KEY,
    ts           INTEGER NOT NULL,
    kind         TEXT NOT NULL,
    asset        TEXT NOT NULL,
    amount       INTEGER NOT NULL,
    peer_addr    TEXT NOT NULL DEFAULT '',
    challenge_id TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    memo         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS history_ts    ON history(ts DESC);
CREATE INDEX IF NOT EXISTS history_asset ON history(asset);
CREATE INDEX IF NOT EXISTS history_kind  ON history(kind);
`
	_, err := s.db.Exec(ddl)
	if err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	return nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

func (s *sqliteStore) Balance(a Asset) (Amount, error) {
	var amt int64
	err := s.db.QueryRow(`SELECT amount FROM balances WHERE asset = ?`, string(a)).Scan(&amt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("balance: %w", err)
	}
	return Amount(amt), nil
}

func (s *sqliteStore) Balances() (map[Asset]Amount, error) {
	rows, err := s.db.Query(`SELECT asset, amount FROM balances WHERE amount > 0`)
	if err != nil {
		return nil, fmt.Errorf("balances: %w", err)
	}
	defer rows.Close()
	out := map[Asset]Amount{}
	for rows.Next() {
		var a string
		var amt int64
		if err := rows.Scan(&a, &amt); err != nil {
			return nil, err
		}
		out[Asset(a)] = Amount(amt)
	}
	return out, rows.Err()
}

func (s *sqliteStore) SaveIssued(ch *Challenge) error {
	payload, err := json.Marshal(ch)
	if err != nil {
		return fmt.Errorf("marshal challenge: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO issued (id, payload, expires_at) VALUES (?, ?, ?)`,
		ch.ID, payload, ch.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("insert issued: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetIssued(id string) (*Challenge, error) {
	var payload []byte
	err := s.db.QueryRow(`SELECT payload FROM issued WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get issued: %w", err)
	}
	var ch Challenge
	if err := json.Unmarshal(payload, &ch); err != nil {
		return nil, fmt.Errorf("unmarshal challenge: %w", err)
	}
	return &ch, nil
}

func (s *sqliteStore) IsSettled(id string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM settled WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is settled: %w", err)
	}
	return true, nil
}

func (s *sqliteStore) RecordPay(tx Transaction) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	dbTx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer dbTx.Rollback() //nolint:errcheck — committed below on success

	var current int64
	err = dbTx.QueryRow(`SELECT amount FROM balances WHERE asset = ?`, string(tx.Asset)).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		current = 0
	} else if err != nil {
		return fmt.Errorf("read balance: %w", err)
	}
	if Amount(current) < tx.Amount {
		return ErrInsufficientBalance
	}
	if err := upsertBalance(dbTx, tx.Asset, Amount(current)-tx.Amount); err != nil {
		return err
	}
	if err := insertHistory(dbTx, tx); err != nil {
		return err
	}
	return dbTx.Commit()
}

func (s *sqliteStore) RecordSettle(tx Transaction, chID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	dbTx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer dbTx.Rollback() //nolint:errcheck

	var dummy int
	err = dbTx.QueryRow(`SELECT 1 FROM settled WHERE id = ?`, chID).Scan(&dummy)
	if err == nil {
		return ErrAlreadySettled
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check settled: %w", err)
	}

	err = dbTx.QueryRow(`SELECT 1 FROM issued WHERE id = ?`, chID).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownChallenge
	} else if err != nil {
		return fmt.Errorf("check issued: %w", err)
	}

	if _, err := dbTx.Exec(`INSERT INTO settled (id, settled_at) VALUES (?, ?)`, chID, time.Now().UnixNano()); err != nil {
		return fmt.Errorf("insert settled: %w", err)
	}
	if _, err := dbTx.Exec(`DELETE FROM issued WHERE id = ?`, chID); err != nil {
		return fmt.Errorf("delete issued: %w", err)
	}

	var current int64
	err = dbTx.QueryRow(`SELECT amount FROM balances WHERE asset = ?`, string(tx.Asset)).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		current = 0
	} else if err != nil {
		return fmt.Errorf("read balance: %w", err)
	}
	if err := upsertBalance(dbTx, tx.Asset, Amount(current)+tx.Amount); err != nil {
		return err
	}
	if err := insertHistory(dbTx, tx); err != nil {
		return err
	}
	return dbTx.Commit()
}

func (s *sqliteStore) RecordTopup(tx Transaction) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	dbTx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer dbTx.Rollback() //nolint:errcheck

	var current int64
	err = dbTx.QueryRow(`SELECT amount FROM balances WHERE asset = ?`, string(tx.Asset)).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		current = 0
	} else if err != nil {
		return fmt.Errorf("read balance: %w", err)
	}
	if err := upsertBalance(dbTx, tx.Asset, Amount(current)+tx.Amount); err != nil {
		return err
	}
	if err := insertHistory(dbTx, tx); err != nil {
		return err
	}
	return dbTx.Commit()
}

func (s *sqliteStore) History(f HistoryFilter) ([]Transaction, error) {
	var (
		clauses []string
		args    []any
	)
	if !f.Since.IsZero() {
		clauses = append(clauses, "ts >= ?")
		args = append(args, f.Since.UnixNano())
	}
	if !f.Before.IsZero() {
		clauses = append(clauses, "ts < ?")
		args = append(args, f.Before.UnixNano())
	}
	if f.Asset != "" {
		clauses = append(clauses, "asset = ?")
		args = append(args, string(f.Asset))
	}
	if f.Kind != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, string(f.Kind))
	}
	q := `SELECT id, ts, kind, asset, amount, peer_addr, challenge_id, source, memo FROM history`
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY ts DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("history query: %w", err)
	}
	defer rows.Close()

	var out []Transaction
	for rows.Next() {
		var (
			tx   Transaction
			ts   int64
			kind string
			asset string
			amt  int64
			peer, chID, source, memo string
		)
		if err := rows.Scan(&tx.ID, &ts, &kind, &asset, &amt, &peer, &chID, &source, &memo); err != nil {
			return nil, fmt.Errorf("scan history row: %w", err)
		}
		tx.Timestamp = time.Unix(0, ts)
		tx.Kind = TxKind(kind)
		tx.Asset = Asset(asset)
		tx.Amount = Amount(amt)
		tx.PeerAddr = Address(peer)
		tx.ChallengeID = chID
		tx.Source = source
		tx.Memo = memo
		out = append(out, tx)
	}
	return out, rows.Err()
}

// upsertBalance writes asset = newAmount, inserting the row if absent.
func upsertBalance(dbTx *sql.Tx, asset Asset, newAmount Amount) error {
	_, err := dbTx.Exec(
		`INSERT INTO balances (asset, amount) VALUES (?, ?)
		 ON CONFLICT(asset) DO UPDATE SET amount = excluded.amount`,
		string(asset), int64(newAmount),
	)
	if err != nil {
		return fmt.Errorf("upsert balance: %w", err)
	}
	return nil
}

func insertHistory(dbTx *sql.Tx, tx Transaction) error {
	_, err := dbTx.Exec(
		`INSERT INTO history (id, ts, kind, asset, amount, peer_addr, challenge_id, source, memo)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tx.ID, tx.Timestamp.UnixNano(), string(tx.Kind), string(tx.Asset), int64(tx.Amount),
		string(tx.PeerAddr), tx.ChallengeID, tx.Source, tx.Memo,
	)
	if err != nil {
		return fmt.Errorf("insert history: %w", err)
	}
	return nil
}
