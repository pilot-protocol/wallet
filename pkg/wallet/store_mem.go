package wallet

import "sync"

// memoryStore is a volatile in-process Store. Useful for tests, for
// stateless wallet daemons in containers, or as a reference impl when
// debugging sqliteStore behavior.
type memoryStore struct {
	mu       sync.Mutex
	balances map[Asset]Amount
	issued   map[string]*Challenge
	settled  map[string]struct{}
	history  []Transaction
}

// NewMemoryStore returns a fresh empty in-memory Store.
func NewMemoryStore() Store {
	return &memoryStore{
		balances: map[Asset]Amount{},
		issued:   map[string]*Challenge{},
		settled:  map[string]struct{}{},
	}
}

func (s *memoryStore) Close() error { return nil }

func (s *memoryStore) Balance(a Asset) (Amount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.balances[a], nil
}

func (s *memoryStore) Balances() (map[Asset]Amount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[Asset]Amount, len(s.balances))
	for k, v := range s.balances {
		if v > 0 {
			out[k] = v
		}
	}
	return out, nil
}

func (s *memoryStore) SaveIssued(ch *Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *ch
	s.issued[ch.ID] = &cp
	return nil
}

func (s *memoryStore) GetIssued(id string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.issued[id]
	if !ok {
		return nil, nil
	}
	cp := *ch
	return &cp, nil
}

func (s *memoryStore) IsSettled(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.settled[id]
	return ok, nil
}

func (s *memoryStore) RecordPay(tx Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.balances[tx.Asset] < tx.Amount {
		return ErrInsufficientBalance
	}
	s.balances[tx.Asset] -= tx.Amount
	s.history = append(s.history, tx)
	return nil
}

func (s *memoryStore) RecordSettle(tx Transaction, chID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.settled[chID]; dup {
		return ErrAlreadySettled
	}
	if _, ok := s.issued[chID]; !ok {
		return ErrUnknownChallenge
	}
	s.settled[chID] = struct{}{}
	delete(s.issued, chID)
	s.balances[tx.Asset] += tx.Amount
	s.history = append(s.history, tx)
	return nil
}

func (s *memoryStore) RecordTopup(tx Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.balances[tx.Asset] += tx.Amount
	s.history = append(s.history, tx)
	return nil
}

func (s *memoryStore) History(f HistoryFilter) ([]Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Transaction, 0, len(s.history))
	for _, tx := range s.history {
		if !f.Since.IsZero() && tx.Timestamp.Before(f.Since) {
			continue
		}
		if !f.Before.IsZero() && !tx.Timestamp.Before(f.Before) {
			continue
		}
		if f.Asset != "" && tx.Asset != f.Asset {
			continue
		}
		if f.Kind != "" && tx.Kind != f.Kind {
			continue
		}
		out = append(out, tx)
	}
	sortHistoryDesc(out)
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}
