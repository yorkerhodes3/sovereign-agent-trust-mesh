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

// TestMemoryByID covers the lookup attestation check V6 depends on.
//
// A superseded binding must stay RESOLVABLE while reporting active=false:
// "your binding was replaced" and "no such binding" are different conditions
// and deserve different denials.
func TestMemoryByID(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	first := &binding.Record{
		ID: "bnd_aaaaaaaaaaaaaaaaaaaaaaaa", CAID: "caid-1",
		PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1", SidecarKey: "ed25519:key-a",
	}
	if err := s.Commit(ctx, first); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, active, found := s.ByID(ctx, first.ID)
	if !found || !active {
		t.Fatalf("found=%v active=%v, want both true", found, active)
	}
	if got.SidecarKey != "ed25519:key-a" {
		t.Fatalf("sidecarKey = %q", got.SidecarKey)
	}

	// Re-bind the same agent.
	second := &binding.Record{
		ID: "bnd_bbbbbbbbbbbbbbbbbbbbbbbb", CAID: "caid-1",
		PeerID: "peer-b", AgentWallet: "0xaaaa", Nonce: "n2", SidecarKey: "ed25519:key-b",
	}
	if err := s.Commit(ctx, second); err != nil {
		t.Fatalf("rebind: %v", err)
	}

	_, active, found = s.ByID(ctx, first.ID)
	if !found {
		t.Fatal("the superseded binding became unresolvable; V6 could not explain the denial")
	}
	if active {
		t.Fatal("the superseded binding still reports active")
	}

	_, active, found = s.ByID(ctx, second.ID)
	if !found || !active {
		t.Fatalf("the new binding: found=%v active=%v, want both true", found, active)
	}

	if _, _, found = s.ByID(ctx, "bnd_ffffffffffffffffffffffff"); found {
		t.Fatal("an unknown binding id was reported as found")
	}
}

// TestMemoryByIDReturnsACopy prevents a caller mutating stored state through a
// returned pointer.
func TestMemoryByIDReturnsACopy(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	if err := s.Commit(ctx, &binding.Record{
		ID: "bnd_aaaaaaaaaaaaaaaaaaaaaaaa", CAID: "caid-1",
		PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	first, _, _ := s.ByID(ctx, "bnd_aaaaaaaaaaaaaaaaaaaaaaaa")
	first.PeerID = "tampered"

	second, _, _ := s.ByID(ctx, "bnd_aaaaaaaaaaaaaaaaaaaaaaaa")
	if second.PeerID != "peer-a" {
		t.Fatalf("PeerID = %q; ByID aliases stored state", second.PeerID)
	}
}

// TestMemoryActiveRecords is what the reconciler sweeps.
func TestMemoryActiveRecords(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	records, err := s.ActiveRecords(ctx)
	if err != nil {
		t.Fatalf("ActiveRecords: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("empty store returned %d records", len(records))
	}

	for i, caid := range []string{"caid-1", "caid-2", "caid-3"} {
		if err := s.Commit(ctx, &binding.Record{
			ID:     "bnd_" + string(rune('a'+i)) + "00000000000000000000000",
			CAID:   caid,
			PeerID: "peer-" + caid,
			// Distinct wallets: sharing one would retire the earlier binding.
			AgentWallet: "0x" + string(rune('a'+i)),
			Nonce:       "nonce-" + caid,
		}); err != nil {
			t.Fatalf("Commit %s: %v", caid, err)
		}
	}

	records, err = s.ActiveRecords(ctx)
	if err != nil {
		t.Fatalf("ActiveRecords: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("ActiveRecords returned %d, want 3", len(records))
	}

	// Revoking one removes it from the sweep set.
	if _, err := s.Revoke(ctx, "bnd_a00000000000000000000000", "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	records, _ = s.ActiveRecords(ctx)
	if len(records) != 2 {
		t.Fatalf("after revocation ActiveRecords returned %d, want 2", len(records))
	}

	// Mutating a returned record must not affect the store.
	records[0].PeerID = "tampered"
	again, _ := s.ActiveRecords(ctx)
	for _, r := range again {
		if r.PeerID == "tampered" {
			t.Fatal("ActiveRecords aliases stored state")
		}
	}
}

func TestMemoryRevocationReason(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	rec := &binding.Record{
		ID: "bnd_aaaaaaaaaaaaaaaaaaaaaaaa", CAID: "caid-1",
		PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}
	if err := s.Commit(ctx, rec); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if _, ok := s.RevocationReason(rec.ID); ok {
		t.Fatal("a live binding reported a revocation reason")
	}
	if _, err := s.Revoke(ctx, rec.ID, "binding.agent_wallet_unset"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	reason, ok := s.RevocationReason(rec.ID)
	if !ok || reason != "binding.agent_wallet_unset" {
		t.Fatalf("reason = %q (recorded=%v)", reason, ok)
	}
}
