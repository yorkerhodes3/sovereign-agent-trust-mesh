// Package store provides NonceStore implementations.
//
// The in-memory store here is fully functional and is what the devnet demo and
// the test suite run against. It is NOT suitable for a multi-replica broker:
// its atomicity guarantee is a process-local mutex, so two broker processes
// sharing no state would each accept the same nonce once. Deployments beyond a
// single instance need the Postgres store (internal/pgstore), where the
// guarantee comes from a UNIQUE constraint instead.
package store

import (
	"context"
	"sync"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// Memory is an in-process NonceStore.
type Memory struct {
	mu sync.Mutex

	// nonces is the consumed-nonce set. Entries are retained even when the
	// binding they belong to is revoked: releasing a nonce would make the
	// original signed document replayable, which is precisely what B3 exists to
	// prevent.
	nonces map[string]time.Time

	// active maps CAID -> the currently live record.
	active map[string]*binding.Record

	// byID indexes every record ever committed, live or not.
	//
	// Superseded records stay resolvable on purpose: attestation check V6 needs
	// to distinguish "this binding was replaced" from "no such binding", and the
	// first deserves a specific denial rather than a generic one.
	byID map[string]*binding.Record

	// walletToCAID supports the B9a uniqueness check.
	walletToCAID map[string]string

	// revoked keeps superseded records for audit.
	revoked []*binding.Record

	// revocationReasons records WHY a binding was retired, which is what an
	// operator actually needs when an agent stops working.
	revocationReasons map[string]string
}

var _ binding.NonceStore = (*Memory)(nil)

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		nonces:            map[string]time.Time{},
		active:            map[string]*binding.Record{},
		byID:              map[string]*binding.Record{},
		walletToCAID:      map[string]string{},
		revocationReasons: map[string]string{},
	}
}

// Seen implements check B3.
func (m *Memory) Seen(_ context.Context, nonce string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.nonces[nonce]
	return ok, nil
}

// Commit implements check B15 atomically.
//
// The nonce test-and-set happens under the SAME lock as the binding write. Doing
// the check in Seen and the write here without re-checking would leave a window
// in which two concurrent submissions both pass B3.
func (m *Memory) Commit(_ context.Context, r *binding.Record) error {
	if r == nil {
		return binding.ErrNonceReused // defensive: never silently accept a nil write
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Re-check inside the critical section. This is the atomicity guarantee.
	if _, ok := m.nonces[r.Nonce]; ok {
		return binding.ErrNonceReused
	}
	m.nonces[r.Nonce] = time.Now().UTC()

	// Retire any prior binding for this CAID, in the same critical section, so
	// an agent never has two live peer identities.
	if prior, ok := m.active[r.CAID]; ok {
		m.revoked = append(m.revoked, prior)
		if prior.AgentWallet != r.AgentWallet {
			delete(m.walletToCAID, prior.AgentWallet)
		}
	}

	stored := *r // copy so a caller mutating its Record cannot alter committed state
	m.active[r.CAID] = &stored
	m.byID[r.ID] = &stored
	m.walletToCAID[r.AgentWallet] = r.CAID
	return nil
}

// ByID resolves a binding by its record id and reports whether it is still the
// active binding for its agent.
//
// Used by attestation check V6. Returning superseded records rather than hiding
// them is deliberate: "your binding was replaced" and "no such binding" call for
// different operator responses, and collapsing them loses that signal.
func (m *Memory) ByID(_ context.Context, bindingID string) (rec *binding.Record, active bool, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.byID[bindingID]
	if !ok {
		return nil, false, false
	}
	current, ok := m.active[r.CAID]
	isActive := ok && current.ID == bindingID

	copied := *r
	return &copied, isActive, true
}

// ActiveByWallet implements check B9a.
func (m *Memory) ActiveByWallet(_ context.Context, wallet string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.walletToCAID[wallet], nil
}

// ActiveByCAID returns the live record for a CAID, if any. Used by the API layer
// to answer lookups; not part of the NonceStore port.
func (m *Memory) ActiveByCAID(_ context.Context, caid string) (*binding.Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.active[caid]
	if !ok {
		return nil, false
	}
	copied := *r
	return &copied, true
}

// RevokedCount reports how many bindings have been superseded. Exposed for
// metrics and tests.
func (m *Memory) RevokedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.revoked)
}

// ActiveRecords returns a snapshot of every live binding.
//
// Returns copies, and holds the lock only for the duration of the copy: the
// reconciler makes chain and HTTP calls per record, and holding a store lock
// across network I/O would stall every concurrent binding submission.
func (m *Memory) ActiveRecords(_ context.Context) ([]*binding.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*binding.Record, 0, len(m.active))
	for _, r := range m.active {
		copied := *r
		out = append(out, &copied)
	}
	return out, nil
}

// Revoke retires a binding by id.
//
// The nonce is NOT released. A revoked binding's document is still a validly
// signed document, so recycling its nonce would make it replayable -- the agent
// could re-admit itself with the very document that was just revoked.
func (m *Memory) Revoke(_ context.Context, bindingID, reason string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.byID[bindingID]
	if !ok {
		return false, nil
	}
	current, isActive := m.active[rec.CAID]
	if !isActive || current.ID != bindingID {
		// Already superseded or revoked. Idempotent by design: the reconciler
		// may race with a re-bind, and a spurious error there would look like a
		// reconciliation failure rather than a no-op.
		return false, nil
	}

	delete(m.active, rec.CAID)
	if m.walletToCAID[rec.AgentWallet] == rec.CAID {
		delete(m.walletToCAID, rec.AgentWallet)
	}
	m.revoked = append(m.revoked, current)
	m.revocationReasons[bindingID] = reason
	return true, nil
}

// RevocationReason returns why a binding was revoked, if it was.
func (m *Memory) RevocationReason(bindingID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.revocationReasons[bindingID]
	return r, ok
}
