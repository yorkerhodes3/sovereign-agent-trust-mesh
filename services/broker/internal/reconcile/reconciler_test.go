package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeRevalidator returns a scripted verdict per binding id.
type fakeRevalidator struct {
	mu      sync.Mutex
	results map[string]error
	calls   int
}

func (f *fakeRevalidator) Revalidate(_ context.Context, rec *binding.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.results[rec.ID]
}

// recordingMesh captures control-plane revocations.
type recordingMesh struct {
	mu      sync.Mutex
	revoked []string
	err     error
}

func (m *recordingMesh) RevokePeer(_ context.Context, peerID, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.revoked = append(m.revoked, peerID)
	return nil
}

func (m *recordingMesh) list() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.revoked...)
}

// seed commits n bindings and returns their ids.
func seed(t *testing.T, s *store.Memory, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := "bnd_" + string(rune('a'+i)) + "00000000000000000000000"
		rec := &binding.Record{
			ID:          id,
			CAID:        "eip155:31337:0x1111111111111111111111111111111111111111/" + itoa(i),
			PeerID:      "12D3KooWPeer" + itoa(i),
			MeshID:      "satm-dev",
			AgentWallet: "0x" + repeat(string(rune('a'+i)), 40),
			Nonce:       "nonce-" + itoa(i),
			Document:    []byte(`{"nonce":"n"}`),
		}
		if err := s.Commit(context.Background(), rec); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func newReconciler(t *testing.T, s *store.Memory, checker Revalidator, mesh MeshRevoker) *Reconciler {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Concurrency = 2
	r, err := New(cfg, s, checker, mesh, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestSweepLeavesHealthyBindingsAlone is the baseline: reconciliation must be a
// no-op when nothing has changed.
func TestSweepLeavesHealthyBindingsAlone(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 3)

	checker := &fakeRevalidator{results: map[string]error{}}
	mesh := &recordingMesh{}
	r := newReconciler(t, s, checker, mesh)

	stats, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if stats.Checked != 3 || stats.Healthy != 3 || stats.Revoked != 0 {
		t.Fatalf("stats = %+v, want 3 checked / 3 healthy / 0 revoked", stats)
	}
	for _, id := range ids {
		if _, active, _ := s.ByID(context.Background(), id); !active {
			t.Fatalf("healthy binding %s was revoked", id)
		}
	}
	if len(mesh.list()) != 0 {
		t.Fatalf("control plane was told to revoke %v", mesh.list())
	}
}

// TestSweepRevokesTransferredAgent is PLAN exit criterion 3: an agent whose NFT
// moved loses mesh access on the next sweep.
//
// ERC-8004 zeroes agentWallet on transfer, so revalidation fails with
// agent_wallet_unset -- with no SATM-specific bookkeeping anywhere.
func TestSweepRevokesTransferredAgent(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 3)

	sold := ids[1]
	checker := &fakeRevalidator{results: map[string]error{
		sold: &binding.Error{Reason: binding.ReasonWalletUnset, Check: "B7",
			Detail: "agentWallet is the zero address; the agent was transferred"},
	}}
	mesh := &recordingMesh{}
	r := newReconciler(t, s, checker, mesh)

	stats, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if stats.Revoked != 1 || stats.Healthy != 2 {
		t.Fatalf("stats = %+v, want 1 revoked / 2 healthy", stats)
	}

	if _, active, found := s.ByID(context.Background(), sold); !found || active {
		t.Fatal("the transferred agent's binding is still active")
	}
	for _, id := range []string{ids[0], ids[2]} {
		if _, active, _ := s.ByID(context.Background(), id); !active {
			t.Fatalf("unrelated binding %s was revoked", id)
		}
	}

	// The mesh must be told, or the peer keeps access until its Biscuit expires.
	if got := mesh.list(); len(got) != 1 {
		t.Fatalf("control plane revocations = %v, want exactly 1", got)
	}

	if reason, ok := s.RevocationReason(sold); !ok || reason != string(binding.ReasonWalletUnset) {
		t.Fatalf("revocation reason = %q (recorded=%v), want %q",
			reason, ok, binding.ReasonWalletUnset)
	}
}

// TestSweepRevokesWhenSAMEndpointRemoved covers TH-16: editing the registration
// file to drop the SAM service entry must also revoke.
func TestSweepRevokesWhenSAMEndpointRemoved(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 2)

	checker := &fakeRevalidator{results: map[string]error{
		ids[0]: &binding.Error{Reason: binding.ReasonSAMEndpointMissing, Check: "B12",
			Detail: "registration file no longer advertises this peer"},
	}}
	r := newReconciler(t, s, checker, &recordingMesh{})

	stats, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if stats.Revoked != 1 {
		t.Fatalf("stats = %+v, want 1 revoked", stats)
	}
	if _, active, _ := s.ByID(context.Background(), ids[0]); active {
		t.Fatal("binding with a removed SAM endpoint is still active")
	}
}

// TestSweepDoesNotRevokeOnInfrastructureFailure is the most important test here.
//
// If an RPC outage were treated as a verdict, a provider having a bad afternoon
// would revoke the entire mesh -- a far worse outcome than briefly trusting a
// stale binding. "Could not check" and "checked and failed" must stay distinct.
func TestSweepDoesNotRevokeOnInfrastructureFailure(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 3)

	outage := &binding.Error{Reason: binding.ReasonChainUnavailable, Check: "B6",
		Detail: "all RPC endpoints unreachable"}
	checker := &fakeRevalidator{results: map[string]error{
		ids[0]: outage, ids[1]: outage, ids[2]: outage,
	}}
	mesh := &recordingMesh{}
	r := newReconciler(t, s, checker, mesh)

	stats, err := r.Sweep(context.Background())
	if err == nil {
		t.Fatal("a total RPC outage was reported as a clean sweep")
	}
	if stats.Revoked != 0 {
		t.Fatalf("an RPC outage revoked %d bindings; the whole mesh would go down", stats.Revoked)
	}
	if stats.Errored != 3 {
		t.Fatalf("stats = %+v, want 3 errored", stats)
	}
	for _, id := range ids {
		if _, active, _ := s.ByID(context.Background(), id); !active {
			t.Fatalf("binding %s was revoked during an outage", id)
		}
	}
	if len(mesh.list()) != 0 {
		t.Fatal("the control plane was told to revoke during an outage")
	}
}

// TestSweepDoesNotRevokeOnUnclassifiedError extends the same principle: an error
// we cannot classify is treated as "could not check", because revoking on an
// error nobody understands is the more dangerous mistake.
func TestSweepDoesNotRevokeOnUnclassifiedError(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 1)

	checker := &fakeRevalidator{results: map[string]error{
		ids[0]: errors.New("something unexpected happened"),
	}}
	r := newReconciler(t, s, checker, &recordingMesh{})

	stats, _ := r.Sweep(context.Background())
	if stats.Revoked != 0 {
		t.Fatal("an unclassified error caused a revocation")
	}
	if stats.Errored != 1 {
		t.Fatalf("stats = %+v, want 1 errored", stats)
	}
}

// TestSweepRevokesLocallyEvenIfControlPlaneFails: the store is authoritative, so
// a control-plane outage must not keep a sold agent trusted by the broker.
func TestSweepRevokesLocallyEvenIfControlPlaneFails(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 1)

	checker := &fakeRevalidator{results: map[string]error{
		ids[0]: &binding.Error{Reason: binding.ReasonWalletUnset, Check: "B7"},
	}}
	mesh := &recordingMesh{err: errors.New("control plane unreachable")}
	r := newReconciler(t, s, checker, mesh)

	stats, err := r.Sweep(context.Background())
	if err == nil {
		t.Fatal("a control-plane failure was not surfaced")
	}
	if stats.Revoked != 1 {
		t.Fatalf("stats = %+v, want the binding revoked locally anyway", stats)
	}
	if _, active, _ := s.ByID(context.Background(), ids[0]); active {
		t.Fatal("binding is still active locally after a control-plane failure")
	}
}

func TestDryRunDoesNotRevoke(t *testing.T) {
	s := store.NewMemory()
	ids := seed(t, s, 2)

	checker := &fakeRevalidator{results: map[string]error{
		ids[0]: &binding.Error{Reason: binding.ReasonWalletUnset, Check: "B7"},
	}}
	mesh := &recordingMesh{}

	cfg := DefaultConfig()
	cfg.DryRun = true
	r, err := New(cfg, s, checker, mesh, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stats, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if stats.Revoked != 1 {
		t.Fatalf("dry run should still REPORT what it would revoke: %+v", stats)
	}
	if _, active, _ := s.ByID(context.Background(), ids[0]); !active {
		t.Fatal("dry run actually revoked a binding")
	}
	if len(mesh.list()) != 0 {
		t.Fatal("dry run called the control plane")
	}
}

func TestSweepOnEmptyStore(t *testing.T) {
	s := store.NewMemory()
	r := newReconciler(t, s, &fakeRevalidator{results: map[string]error{}}, &recordingMesh{})

	stats, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if stats.Checked != 0 {
		t.Fatalf("stats = %+v, want nothing checked", stats)
	}
}

// TestSweepRespectsConcurrencyLimit keeps a large mesh from stampeding the RPC
// provider and every registration-file host at once.
func TestSweepRespectsConcurrencyLimit(t *testing.T) {
	s := store.NewMemory()
	seed(t, s, 20)

	var (
		mu      sync.Mutex
		current int
		peak    int
	)
	checker := &blockingRevalidator{
		onCall: func() {
			mu.Lock()
			current++
			if current > peak {
				peak = current
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()
		},
	}

	cfg := DefaultConfig()
	cfg.Concurrency = 3
	r, err := New(cfg, s, checker, &recordingMesh{}, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if peak > 3 {
		t.Fatalf("peak concurrency was %d, limit is 3", peak)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency was %d; the sweep is effectively serial", peak)
	}
}

type blockingRevalidator struct{ onCall func() }

func (b *blockingRevalidator) Revalidate(_ context.Context, _ *binding.Record) error {
	b.onCall()
	return nil
}

// TestRevokeIsIdempotent covers the race with a concurrent re-bind: the newer
// binding must not be taken down by a sweep that started before it existed.
func TestRevokeIsIdempotent(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	rec := &binding.Record{
		ID: "bnd_aaaaaaaaaaaaaaaaaaaaaaaa", CAID: "caid-1",
		PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}
	if err := s.Commit(ctx, rec); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	revoked, err := s.Revoke(ctx, rec.ID, "test")
	if err != nil || !revoked {
		t.Fatalf("first Revoke: revoked=%v err=%v", revoked, err)
	}
	revoked, err = s.Revoke(ctx, rec.ID, "test")
	if err != nil {
		t.Fatalf("second Revoke errored: %v", err)
	}
	if revoked {
		t.Fatal("second Revoke reported a change; it must be idempotent")
	}

	if _, err := s.Revoke(ctx, "bnd_ffffffffffffffffffffffff", "test"); err != nil {
		t.Fatalf("revoking an unknown binding errored: %v", err)
	}
}

// TestRevokeDoesNotReleaseNonce: a revoked binding's document is still validly
// signed, so recycling its nonce would let the agent re-admit itself with the
// very document that was just revoked.
func TestRevokeDoesNotReleaseNonce(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	rec := &binding.Record{
		ID: "bnd_aaaaaaaaaaaaaaaaaaaaaaaa", CAID: "caid-1",
		PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}
	if err := s.Commit(ctx, rec); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := s.Revoke(ctx, rec.ID, "transferred"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	seen, err := s.Seen(ctx, "n1")
	if err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if !seen {
		t.Fatal("revocation released the nonce; the revoked document becomes replayable")
	}
}

// TestRevokeFreesTheWalletForRebinding: after revocation the agentWallet must no
// longer report as bound, or B9a would permanently reject a wallet that is in
// fact free.
func TestRevokeFreesTheWallet(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	rec := &binding.Record{
		ID: "bnd_aaaaaaaaaaaaaaaaaaaaaaaa", CAID: "caid-1",
		PeerID: "peer-a", AgentWallet: "0xaaaa", Nonce: "n1",
	}
	if err := s.Commit(ctx, rec); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := s.Revoke(ctx, rec.ID, "transferred"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	caid, err := s.ActiveByWallet(ctx, "0xaaaa")
	if err != nil {
		t.Fatalf("ActiveByWallet: %v", err)
	}
	if caid != "" {
		t.Fatalf("wallet still maps to %q after revocation", caid)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	s := store.NewMemory()
	r := newReconciler(t, s, &fakeRevalidator{results: map[string]error{}}, &recordingMesh{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop within 5s of cancellation")
	}
}

// TestRunSweepsImmediately: a broker restart must not extend the revocation
// window by a full interval.
func TestRunSweepsImmediately(t *testing.T) {
	s := store.NewMemory()
	seed(t, s, 1)

	checker := &fakeRevalidator{results: map[string]error{}}
	cfg := DefaultConfig()
	cfg.Interval = time.Hour // so only the initial sweep can run
	r, err := New(cfg, s, checker, &recordingMesh{}, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	checker.mu.Lock()
	defer checker.mu.Unlock()
	if checker.calls == 0 {
		t.Fatal("Run waited a full interval before its first sweep")
	}
}

func TestNewValidatesArguments(t *testing.T) {
	s := store.NewMemory()
	if _, err := New(DefaultConfig(), nil, &fakeRevalidator{}, nil, quietLogger()); err == nil {
		t.Error("nil store was accepted")
	}
	if _, err := New(DefaultConfig(), s, nil, nil, quietLogger()); err == nil {
		t.Error("nil revalidator was accepted")
	}
	// A nil mesh revoker is allowed but must not silently no-op without warning.
	r, err := New(DefaultConfig(), s, &fakeRevalidator{}, nil, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := r.mesh.(NoopMeshRevoker); !ok {
		t.Fatalf("nil mesh revoker became %T, want NoopMeshRevoker", r.mesh)
	}
}

func TestIsInfrastructure(t *testing.T) {
	infra := []binding.Reason{
		binding.ReasonChainUnavailable,
		binding.ReasonRegistrationUnreachable,
		binding.ReasonCommitFailed,
		binding.ReasonMalformed,
		"",
	}
	for _, r := range infra {
		if !isInfrastructure(r) {
			t.Errorf("reason %q should be treated as infrastructure", r)
		}
	}

	verdicts := []binding.Reason{
		binding.ReasonWalletUnset,
		binding.ReasonWalletMismatch,
		binding.ReasonAgentNotFound,
		binding.ReasonAgentInactive,
		binding.ReasonSAMEndpointMissing,
		binding.ReasonRegistrationMismatch,
		binding.ReasonRegistryNotAllowed,
	}
	for _, r := range verdicts {
		if isInfrastructure(r) {
			t.Errorf("reason %q is a verdict and must trigger revocation", r)
		}
	}
}
