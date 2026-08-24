package attest

import (
	"context"
	"sync"
	"time"
)

// MemoryNonceStore is an in-process NonceStore.
//
// Correct for a single sidecar, which is the deployment shape: a sidecar is
// co-located with exactly one agent and is the only thing that serves that
// agent's inbound calls. Unlike the broker -- which may be replicated and
// therefore needs a database constraint -- a sidecar's nonce set has no second
// writer to race with.
type MemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

var _ NonceStore = (*MemoryNonceStore)(nil)

// NewMemoryNonceStore returns an empty store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{
		seen: map[string]time.Time{},
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// Consume atomically records (bindingID, nonce).
//
// The key is the PAIR, not the nonce alone. Two different callers could pick the
// same random nonce without either misbehaving, and rejecting the second would
// be a spurious denial; scoping by binding makes collisions between callers
// harmless while still making replay by one caller impossible.
func (s *MemoryNonceStore) Consume(_ context.Context, bindingID, nonce string, expiresAt time.Time) error {
	key := bindingID + "\x00" + nonce

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.seen[key]; ok {
		return ErrNonceReused
	}
	s.seen[key] = expiresAt
	return nil
}

// Purge drops entries whose attestation has expired.
//
// Safe because an expired attestation is already refused by V7, so its nonce can
// never be usefully replayed. Retention beyond expiry would grow without bound
// for no security benefit.
func (s *MemoryNonceStore) Purge() int {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for k, expires := range s.seen {
		if now.After(expires) {
			delete(s.seen, k)
			removed++
		}
	}
	return removed
}

// Len reports how many nonces are retained. Exposed for metrics and tests.
func (s *MemoryNonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}
