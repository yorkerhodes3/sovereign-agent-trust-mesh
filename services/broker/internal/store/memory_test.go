package store_test

import (
	"context"
	"testing"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store/storetest"
)

// TestMemoryConformance runs the shared NonceStore suite. Any other
// implementation must pass this identical set.
func TestMemoryConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) binding.NonceStore {
		return store.NewMemory()
	})
}

// TestMemoryStoresACopy pins that a caller mutating its Record after Commit
// cannot retroactively alter committed state -- an audit-integrity property the
// SQL store gets for free but an in-process map does not.
func TestMemoryStoresACopy(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	r := &binding.Record{
		ID:          "rec-1",
		CAID:        "eip155:31337:0xabc/0",
		PeerID:      "12D3KooWOriginal",
		AgentWallet: "0xaaaa",
		Nonce:       "n1",
	}
	if err := s.Commit(ctx, r); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	r.PeerID = "12D3KooWTampered"

	got, ok := s.ActiveByCAID(ctx, "eip155:31337:0xabc/0")
	if !ok {
		t.Fatal("record not found")
	}
	if got.PeerID != "12D3KooWOriginal" {
		t.Fatalf("PeerID = %q; committed state was mutated through the caller's pointer", got.PeerID)
	}
}

// TestMemoryReturnsACopy is the read-side half of the same property.
func TestMemoryReturnsACopy(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	if err := s.Commit(ctx, &binding.Record{
		CAID: "caid-1", PeerID: "12D3KooWOriginal", AgentWallet: "0xaaaa", Nonce: "n1",
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	first, _ := s.ActiveByCAID(ctx, "caid-1")
	first.PeerID = "12D3KooWTampered"

	second, _ := s.ActiveByCAID(ctx, "caid-1")
	if second.PeerID != "12D3KooWOriginal" {
		t.Fatalf("PeerID = %q; a returned record aliases stored state", second.PeerID)
	}
}

// TestMemoryTracksRevocations checks the audit trail survives rebinding.
func TestMemoryTracksRevocations(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	if err := s.Commit(ctx, &binding.Record{
		CAID: "caid-1", PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if s.RevokedCount() != 0 {
		t.Fatalf("RevokedCount = %d after first commit, want 0", s.RevokedCount())
	}

	if err := s.Commit(ctx, &binding.Record{
		CAID: "caid-1", PeerID: "peer-b", AgentWallet: "0xaaaa", Nonce: "n2",
	}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if s.RevokedCount() != 1 {
		t.Fatalf("RevokedCount = %d after rebind, want 1", s.RevokedCount())
	}

	got, _ := s.ActiveByCAID(ctx, "caid-1")
	if got.PeerID != "peer-b" {
		t.Fatalf("active PeerID = %q, want peer-b", got.PeerID)
	}
}

// TestMemoryWalletRemapOnRebind covers wallet rotation: when a CAID moves to a
// new wallet the OLD wallet must stop reporting an active binding, or B9a would
// keep rejecting a wallet that is in fact free.
func TestMemoryWalletRemapOnRebind(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	if err := s.Commit(ctx, &binding.Record{
		CAID: "caid-1", PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Commit(ctx, &binding.Record{
		CAID: "caid-1", PeerID: "peer-a", AgentWallet: "0xbbbb", Nonce: "n2",
	}); err != nil {
		t.Fatalf("rebind: %v", err)
	}

	old, err := s.ActiveByWallet(ctx, "0xaaaa")
	if err != nil {
		t.Fatalf("ActiveByWallet(old): %v", err)
	}
	if old != "" {
		t.Fatalf("old wallet still maps to %q; it would be wrongly rejected by B9a", old)
	}

	current, err := s.ActiveByWallet(ctx, "0xbbbb")
	if err != nil {
		t.Fatalf("ActiveByWallet(new): %v", err)
	}
	if current != "caid-1" {
		t.Fatalf("new wallet maps to %q, want caid-1", current)
	}
}

func TestMemoryRejectsNilRecord(t *testing.T) {
	s := store.NewMemory()
	if err := s.Commit(context.Background(), nil); err == nil {
		t.Fatal("nil record was accepted")
	}
}
