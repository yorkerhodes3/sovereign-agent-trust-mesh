// Package storetest is a shared conformance suite for binding.NonceStore.
//
// The NonceStore is where SATM's replay defence actually lives: check B3 asks
// "has this nonce been seen?" and check B15 consumes it. Those are two separate
// operations, so correctness depends entirely on Commit being ATOMIC -- if two
// concurrent submissions can both pass B3 and both commit, the nonce mechanism
// is decorative.
//
// That property is easy to get right in a single-process map and easy to get
// wrong in SQL. Rather than test each implementation separately and hope they
// agree, every implementation runs this identical suite, so "the Postgres store
// behaves like the in-memory store" is a checked claim rather than an assumption.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// Factory returns a fresh, empty store. It is called once per subtest so cases
// cannot leak state into one another.
type Factory func(t *testing.T) binding.NonceStore

// Run executes the full conformance suite.
func Run(t *testing.T, newStore Factory) {
	t.Helper()

	t.Run("UnseenNonceIsNotSeen", func(t *testing.T) { testUnseenNonce(t, newStore) })
	t.Run("CommitMakesNonceSeen", func(t *testing.T) { testCommitMakesSeen(t, newStore) })
	t.Run("NonceReuseRejected", func(t *testing.T) { testNonceReuse(t, newStore) })
	t.Run("ConcurrentCommitAdmitsExactlyOne", func(t *testing.T) { testConcurrentCommit(t, newStore) })
	t.Run("DistinctNoncesCoexist", func(t *testing.T) { testDistinctNonces(t, newStore) })
	t.Run("ActiveByWalletEmptyWhenUnbound", func(t *testing.T) { testActiveByWalletEmpty(t, newStore) })
	t.Run("ActiveByWalletReturnsCAID", func(t *testing.T) { testActiveByWallet(t, newStore) })
	t.Run("RebindingCAIDRevokesPrior", func(t *testing.T) { testRebindRevokesPrior(t, newStore) })
	t.Run("RevocationIsScopedToOneCAID", func(t *testing.T) { testRevocationScoped(t, newStore) })
	t.Run("ContextCancellationRespected", func(t *testing.T) { testContextCancellation(t, newStore) })
}

// rec builds a Record with distinct, valid-looking values.
func rec(nonce, caid, wallet string) *binding.Record {
	now := time.Now().UTC().Truncate(time.Second)
	return &binding.Record{
		ID:              "rec-" + nonce,
		CAID:            caid,
		PeerID:          "12D3KooWTest" + nonce,
		MeshID:          "satm-test-mesh",
		SidecarKey:      "sidecar-" + nonce,
		AgentWallet:     wallet,
		Owner:           wallet,
		Nonce:           nonce,
		Document:        []byte(`{"nonce":"` + nonce + `"}`),
		PeerSignature:   []byte{0x01, 0x02, 0x03},
		WalletSignature: []byte{0x04, 0x05, 0x06},
		DomainVerified:  false,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Hour),
	}
}

const (
	caidA   = "eip155:31337:0x1111111111111111111111111111111111111111/0"
	caidB   = "eip155:31337:0x1111111111111111111111111111111111111111/1"
	walletA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	walletB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func testUnseenNonce(t *testing.T, newStore Factory) {
	s := newStore(t)
	seen, err := s.Seen(context.Background(), "never-used")
	if err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if seen {
		t.Fatal("a nonce that was never committed reported as seen")
	}
}

func testCommitMakesSeen(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.Commit(ctx, rec("n1", caidA, walletA)); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	seen, err := s.Seen(ctx, "n1")
	if err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if !seen {
		t.Fatal("a committed nonce did not report as seen; replay defence is inert")
	}
}

func testNonceReuse(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.Commit(ctx, rec("dup", caidA, walletA)); err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	// A DIFFERENT binding reusing the same nonce -- the replay case.
	second := rec("dup", caidB, walletB)
	err := s.Commit(ctx, second)
	if err == nil {
		t.Fatal("nonce reuse was accepted")
	}
	if !errors.Is(err, binding.ErrNonceReused) {
		t.Fatalf("err = %v, want ErrNonceReused (callers branch on this exact value)", err)
	}
}

// testConcurrentCommit is the reason this suite exists.
//
// B3 (check) and B15 (consume) are separate steps, so the window between them is
// real. Many goroutines racing on one nonce must yield exactly one success.
func testConcurrentCommit(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	const racers = 32
	var wg sync.WaitGroup
	results := make([]error, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := rec("race", fmt.Sprintf("%s-%d", caidA, i), walletA)
			<-start // release all goroutines at once to widen the race window
			results[i] = s.Commit(ctx, r)
		}(i)
	}
	close(start)
	wg.Wait()

	var succeeded, reused, other int
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, binding.ErrNonceReused):
			reused++
		default:
			other++
			t.Errorf("unexpected error: %v", err)
		}
	}

	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent commits on one nonce succeeded, want exactly 1; "+
			"Commit is not atomic and the nonce provides no replay protection", succeeded, racers)
	}
	if reused != racers-1 {
		t.Fatalf("losers: %d ErrNonceReused + %d other, want %d ErrNonceReused",
			reused, other, racers-1)
	}
}

func testDistinctNonces(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		r := rec(fmt.Sprintf("n%d", i), fmt.Sprintf("%s-%d", caidA, i), walletA)
		if err := s.Commit(ctx, r); err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
	}
	for i := 0; i < 10; i++ {
		seen, err := s.Seen(ctx, fmt.Sprintf("n%d", i))
		if err != nil {
			t.Fatalf("Seen %d: %v", i, err)
		}
		if !seen {
			t.Fatalf("nonce n%d not seen after commit", i)
		}
	}
}

func testActiveByWalletEmpty(t *testing.T, newStore Factory) {
	s := newStore(t)
	caid, err := s.ActiveByWallet(context.Background(), walletA)
	if err != nil {
		t.Fatalf("ActiveByWallet: %v", err)
	}
	if caid != "" {
		t.Fatalf("unbound wallet returned CAID %q, want empty", caid)
	}
}

func testActiveByWallet(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.Commit(ctx, rec("w1", caidA, walletA)); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got, err := s.ActiveByWallet(ctx, walletA)
	if err != nil {
		t.Fatalf("ActiveByWallet: %v", err)
	}
	if got != caidA {
		t.Fatalf("ActiveByWallet = %q, want %q", got, caidA)
	}

	// A different wallet must not be affected.
	other, err := s.ActiveByWallet(ctx, walletB)
	if err != nil {
		t.Fatalf("ActiveByWallet(other): %v", err)
	}
	if other != "" {
		t.Fatalf("unrelated wallet returned %q, want empty", other)
	}
}

// testRebindRevokesPrior covers the rotation path: re-binding a CAID to a new
// peer must retire the old binding in the SAME transaction, or the agent
// briefly has two live peer identities.
func testRebindRevokesPrior(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	first := rec("r1", caidA, walletA)
	if err := s.Commit(ctx, first); err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	second := rec("r2", caidA, walletA)
	second.PeerID = "12D3KooWRotated"
	if err := s.Commit(ctx, second); err != nil {
		t.Fatalf("rebind Commit: %v", err)
	}

	got, err := s.ActiveByWallet(ctx, walletA)
	if err != nil {
		t.Fatalf("ActiveByWallet: %v", err)
	}
	if got != caidA {
		t.Fatalf("ActiveByWallet = %q, want %q after rebind", got, caidA)
	}

	// Both nonces stay consumed: revoking a binding must not recycle its nonce.
	for _, n := range []string{"r1", "r2"} {
		seen, err := s.Seen(ctx, n)
		if err != nil {
			t.Fatalf("Seen(%s): %v", n, err)
		}
		if !seen {
			t.Fatalf("nonce %s was released by revocation; it becomes replayable", n)
		}
	}
}

// testRevocationScoped checks the blast radius: committing for one CAID must not
// disturb an unrelated CAID's binding.
func testRevocationScoped(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.Commit(ctx, rec("s1", caidA, walletA)); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if err := s.Commit(ctx, rec("s2", caidB, walletB)); err != nil {
		t.Fatalf("Commit B: %v", err)
	}

	// Rebind A only.
	third := rec("s3", caidA, walletA)
	third.PeerID = "12D3KooWNewA"
	if err := s.Commit(ctx, third); err != nil {
		t.Fatalf("rebind A: %v", err)
	}

	gotB, err := s.ActiveByWallet(ctx, walletB)
	if err != nil {
		t.Fatalf("ActiveByWallet(B): %v", err)
	}
	if gotB != caidB {
		t.Fatalf("unrelated binding B = %q, want %q; revocation over-reached", gotB, caidB)
	}
}

func testContextCancellation(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Implementations backed by a network MUST honour cancellation. An
	// in-process store legitimately may not, so a nil error is acceptable --
	// what is NOT acceptable is hanging or panicking.
	_, _ = s.Seen(ctx, "cancelled")
	_ = s.Commit(ctx, rec("cancelled", caidA, walletA))
	_, _ = s.ActiveByWallet(ctx, walletA)
}
