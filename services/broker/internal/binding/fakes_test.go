package binding

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"time"
)

// This file holds test doubles shared across the binding test suite.
//
// They are deliberately simple in-memory implementations rather than mocks with
// expectations: the tests assert on VERIFIER behaviour, and a mock that also
// asserts call order would couple them to the verifier's internals and make
// legitimate refactors look like failures.

// ---------------------------------------------------------------- chain ----

type fakeAgent struct {
	owner   [20]byte
	wallet  [20]byte
	uri     string
	missing bool
}

type fakeChain struct {
	mu sync.Mutex
	// keyed by registry address + agent id
	agents map[string]*fakeAgent
	// erc1271 wallets that accept any signature for a given digest
	erc1271 map[[20]byte]map[[32]byte]bool
	// failNext forces the next call to return a transport error, for degraded
	// mode tests.
	failOwnerOf bool
	failURI     bool
}

func newFakeChain() *fakeChain {
	return &fakeChain{
		agents:  map[string]*fakeAgent{},
		erc1271: map[[20]byte]map[[32]byte]bool{},
	}
}

func agentKey(registry [20]byte, id *big.Int) string {
	return FormatAddress(registry) + "/" + id.String()
}

func (c *fakeChain) put(registry [20]byte, id *big.Int, a *fakeAgent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agents[agentKey(registry, id)] = a
}

func (c *fakeChain) get(registry [20]byte, id *big.Int) *fakeAgent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agents[agentKey(registry, id)]
}

func (c *fakeChain) OwnerOf(_ context.Context, registry [20]byte, id *big.Int) ([20]byte, error) {
	if c.failOwnerOf {
		return [20]byte{}, errors.New("rpc unavailable")
	}
	a := c.get(registry, id)
	if a == nil || a.missing {
		return [20]byte{}, ErrAgentNotFound
	}
	return a.owner, nil
}

func (c *fakeChain) GetAgentWallet(_ context.Context, registry [20]byte, id *big.Int) ([20]byte, error) {
	a := c.get(registry, id)
	if a == nil {
		return [20]byte{}, ErrAgentNotFound
	}
	return a.wallet, nil
}

func (c *fakeChain) AgentURI(_ context.Context, registry [20]byte, id *big.Int) (string, error) {
	if c.failURI {
		return "", errors.New("rpc unavailable")
	}
	a := c.get(registry, id)
	if a == nil {
		return "", ErrAgentNotFound
	}
	return a.uri, nil
}

func (c *fakeChain) IsValidERC1271Signature(_ context.Context, wallet [20]byte, digest [32]byte, _ []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := c.erc1271[wallet]; ok {
		return m[digest], nil
	}
	return false, nil
}

func (c *fakeChain) allowERC1271(wallet [20]byte, digest [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.erc1271[wallet] == nil {
		c.erc1271[wallet] = map[[32]byte]bool{}
	}
	c.erc1271[wallet][digest] = true
}

// ---------------------------------------------------------------- files ----

type fakeFetcher struct {
	mu    sync.Mutex
	files map[string]*RegistrationFile
	err   error
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{files: map[string]*RegistrationFile{}}
}

func (f *fakeFetcher) put(uri string, file *RegistrationFile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[uri] = file
}

func (f *fakeFetcher) Fetch(_ context.Context, uri string) (*RegistrationFile, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[uri]
	if !ok {
		return nil, errors.New("not found")
	}
	return file, nil
}

// ---------------------------------------------------------------- store ----

// memStore is an in-memory NonceStore whose Commit is genuinely atomic under
// concurrency, so the B15 race test exercises real mutual exclusion rather than
// a store that happens not to interleave.
type memStore struct {
	mu        sync.Mutex
	nonces    map[string]bool
	records   []*Record
	byWallet  map[string]string
	commitErr error
}

func newMemStore() *memStore {
	return &memStore{nonces: map[string]bool{}, byWallet: map[string]string{}}
}

func (s *memStore) Seen(_ context.Context, nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonces[nonce], nil
}

func (s *memStore) Commit(_ context.Context, rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitErr != nil {
		return s.commitErr
	}
	// The UNIQUE constraint the real schema enforces.
	if s.nonces[rec.Nonce] {
		return ErrNonceReused
	}
	s.nonces[rec.Nonce] = true
	// Revoke any prior active binding for this CAID (one active binding per agent).
	kept := s.records[:0]
	for _, r := range s.records {
		if r.CAID != rec.CAID {
			kept = append(kept, r)
		}
	}
	s.records = append(kept, rec)
	s.byWallet[rec.AgentWallet] = rec.CAID
	return nil
}

func (s *memStore) ActiveByWallet(_ context.Context, wallet string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byWallet[wallet], nil
}

func (s *memStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// ---------------------------------------------------------------- clock ----

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}
