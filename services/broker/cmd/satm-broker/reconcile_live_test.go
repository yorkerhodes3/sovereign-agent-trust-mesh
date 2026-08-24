//go:build integration

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/chainrpc"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/fetch"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/reconcile"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store"
)

// anvilBuyer is Anvil account #1: a well-known devnet address used as a
// transfer target.
const anvilBuyer = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"

// buildVerifier assembles a verifier over the live devnet, matching the
// production composition rather than a test double.
func buildVerifier(t *testing.T, registry string) (*binding.Verifier, *store.Memory) {
	t.Helper()

	reg, err := binding.ParseTrustedRegistry("eip155:31337:" + registry)
	if err != nil {
		t.Fatalf("ParseTrustedRegistry: %v", err)
	}

	rpcCfg := chainrpc.DefaultConfig(rpcURL())
	rpcCfg.Quorum = 1
	chain, err := chainrpc.New(rpcCfg)
	if err != nil {
		t.Fatalf("chainrpc: %v", err)
	}

	nonceStore := store.NewMemory()
	v, err := binding.NewVerifier(binding.Config{
		MeshID:                   testMeshID,
		ControlPlane:             testCtrlPlane,
		MaxTTL:                   168 * time.Hour,
		ClockSkew:                time.Minute,
		TrustedRegistries:        []binding.TrustedRegistry{reg},
		RequireUniqueAgentWallet: true,
	}, chain, fetch.New(fetch.DefaultConfig()), nonceStore)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v, nonceStore
}

// commitBinding registers an agent on-chain and admits a binding for it through
// the real HTTP API, returning the committed record.
func commitBinding(t *testing.T, registry string) (*binding.Record, *store.Memory, *binding.Verifier, *agentKeys) {
	t.Helper()

	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	verifier, nonceStore := buildVerifier(t, registry)

	res, err := verifier.Verify(context.Background(), toInput(t, keys, registry, agentID))
	if err != nil {
		t.Fatalf("initial binding rejected: %v", err)
	}
	return res.Record, nonceStore, verifier, keys
}

func toInput(t *testing.T, keys *agentKeys, registry string, agentID *big.Int) binding.Input {
	t.Helper()
	req := buildSubmission(t, keys, registry, agentID)
	return binding.Input{
		Document:        req.Document,
		PeerPublicKey:   req.PeerPublicKey,
		PeerSignature:   req.PeerSignature,
		WalletSignature: req.WalletSignature,
	}
}

// TestLiveReconcileRevokesTransferredAgent is PLAN.md exit criterion 3, and the
// single most convincing demonstration in the prototype: an on-chain ownership
// change propagating into live access control.
//
// Nothing SATM-specific tracks the sale. ERC-8004 zeroes `agentWallet` on
// transfer, the reconciler re-reads it, and the binding fails B7.
func TestLiveReconcileRevokesTransferredAgent(t *testing.T) {
	registry := registryAddress(t)
	rec, nonceStore, verifier, _ := commitBinding(t, registry)
	ctx := context.Background()

	// Precondition: healthy before the transfer.
	r, err := reconcile.New(reconcile.DefaultConfig(), nonceStore, verifier, nil, quietTestLogger())
	if err != nil {
		t.Fatalf("reconcile.New: %v", err)
	}
	stats, err := r.Sweep(ctx)
	if err != nil {
		t.Fatalf("pre-transfer sweep: %v", err)
	}
	if stats.Healthy != 1 || stats.Revoked != 0 {
		t.Fatalf("pre-transfer stats = %+v, want 1 healthy / 0 revoked", stats)
	}

	// Sell the agent.
	agentID := caidAgentID(t, rec.CAID)
	runCast(t, "send", registry,
		"transferFrom(address,address,uint256)",
		anvilAddr, anvilBuyer, agentID.String(),
		"--rpc-url", rpcURL(), "--private-key", anvilPK)

	// Confirm the chain actually reflects the sale, so a failure below is
	// attributable to the reconciler rather than to a failed transaction.
	assertWalletCleared(t, registry, agentID)

	// One sweep later, access is gone.
	stats, err = r.Sweep(ctx)
	if err != nil {
		t.Fatalf("post-transfer sweep: %v", err)
	}
	if stats.Revoked != 1 {
		t.Fatalf("post-transfer stats = %+v, want 1 revoked", stats)
	}

	if _, active, found := nonceStore.ByID(ctx, rec.ID); !found || active {
		t.Fatal("the sold agent's binding is still active")
	}
	reason, ok := nonceStore.RevocationReason(rec.ID)
	if !ok {
		t.Fatal("no revocation reason recorded")
	}
	if reason != string(binding.ReasonWalletUnset) {
		t.Fatalf("revocation reason = %q, want %q", reason, binding.ReasonWalletUnset)
	}
	t.Logf("agent sold on-chain -> binding %s revoked with reason %q", rec.ID, reason)
}

// TestLiveReconcileLeavesHealthyBindingAlone guards the other direction: a
// reconciler that revoked healthy bindings would be worse than none.
func TestLiveReconcileLeavesHealthyBindingAlone(t *testing.T) {
	registry := registryAddress(t)
	rec, nonceStore, verifier, _ := commitBinding(t, registry)
	ctx := context.Background()

	r, err := reconcile.New(reconcile.DefaultConfig(), nonceStore, verifier, nil, quietTestLogger())
	if err != nil {
		t.Fatalf("reconcile.New: %v", err)
	}

	for i := 0; i < 3; i++ {
		stats, err := r.Sweep(ctx)
		if err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
		if stats.Revoked != 0 {
			t.Fatalf("sweep %d revoked a healthy binding: %+v", i, stats)
		}
	}
	if _, active, _ := nonceStore.ByID(ctx, rec.ID); !active {
		t.Fatal("a healthy binding was revoked")
	}
}

// TestLiveReconcileSurvivesRPCOutage proves the fail-safe direction against real
// infrastructure: when the chain is unreachable, bindings stay put.
func TestLiveReconcileSurvivesRPCOutage(t *testing.T) {
	registry := registryAddress(t)
	rec, nonceStore, _, _ := commitBinding(t, registry)
	ctx := context.Background()

	// A verifier pointed at a dead endpoint.
	reg, err := binding.ParseTrustedRegistry("eip155:31337:" + registry)
	if err != nil {
		t.Fatalf("ParseTrustedRegistry: %v", err)
	}
	deadCfg := chainrpc.DefaultConfig("http://127.0.0.1:1")
	deadCfg.Quorum = 1
	deadCfg.Timeout = 300 * time.Millisecond
	deadChain, err := chainrpc.New(deadCfg)
	if err != nil {
		t.Fatalf("chainrpc: %v", err)
	}
	deadVerifier, err := binding.NewVerifier(binding.Config{
		MeshID: testMeshID, ControlPlane: testCtrlPlane,
		MaxTTL: 168 * time.Hour, ClockSkew: time.Minute,
		TrustedRegistries: []binding.TrustedRegistry{reg},
	}, deadChain, fetch.New(fetch.DefaultConfig()), nonceStore)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	r, err := reconcile.New(reconcile.DefaultConfig(), nonceStore, deadVerifier, nil, quietTestLogger())
	if err != nil {
		t.Fatalf("reconcile.New: %v", err)
	}

	stats, err := r.Sweep(ctx)
	if err == nil {
		t.Fatal("an RPC outage was reported as a clean sweep")
	}
	if stats.Revoked != 0 {
		t.Fatalf("an RPC outage revoked %d bindings; the whole mesh would go down", stats.Revoked)
	}
	if _, active, _ := nonceStore.ByID(ctx, rec.ID); !active {
		t.Fatal("a binding was revoked during an RPC outage")
	}
}

// assertWalletCleared confirms the sale actually landed on-chain.
func assertWalletCleared(t *testing.T, registry string, agentID *big.Int) {
	t.Helper()
	out := runCast(t, "call", registry, "getAgentWallet(uint256)(address)",
		agentID.String(), "--rpc-url", rpcURL())
	got := strings.ToLower(lastNonEmptyLine(out))
	if got != "0x0000000000000000000000000000000000000000" {
		t.Fatalf("precondition failed: agentWallet is %s after transfer, want the zero address", got)
	}
}

// caidAgentID extracts the agent id from a CAID.
func caidAgentID(t *testing.T, caid string) *big.Int {
	t.Helper()
	idx := strings.LastIndex(caid, "/")
	if idx < 0 {
		t.Fatalf("malformed CAID %q", caid)
	}
	n, ok := new(big.Int).SetString(caid[idx+1:], 10)
	if !ok {
		t.Fatalf("could not parse agent id from CAID %q", caid)
	}
	return n
}

// TestLiveBindingByIDEndpoint checks the Trust API surface the sidecar reads for
// attestation checks V5 and V6, including that a revoked binding stays
// resolvable but reports active=false.
func TestLiveBindingByIDEndpoint(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	ts, nonceStore := newBrokerServer(t, registry)
	status, body := postBinding(t, ts.URL, buildSubmission(t, keys, registry, agentID))
	if status != http.StatusCreated {
		t.Fatalf("setup failed: %d %v", status, body)
	}
	id := body["id"].(string)

	fetchByID := func() (int, map[string]any) {
		resp, err := http.Get(ts.URL + "/v1/bindings/by-id/" + id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, got := fetchByID()
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if got["active"] != true {
		t.Fatalf("active = %v, want true", got["active"])
	}
	if got["sidecarKey"] != keys.sidecarKey {
		t.Fatalf("sidecarKey = %v, want %s", got["sidecarKey"], keys.sidecarKey)
	}

	// Revoke, then confirm the record is still resolvable but inactive: check V6
	// needs to tell "replaced" apart from "unknown".
	if _, err := nonceStore.Revoke(context.Background(), id, "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	code, got = fetchByID()
	if code != http.StatusOK {
		t.Fatalf("a revoked binding became unresolvable (status %d); "+
			"V6 could not distinguish it from an unknown binding", code)
	}
	if got["active"] != false {
		t.Fatalf("active = %v after revocation, want false", got["active"])
	}

	// An id that was never issued must still be a 404.
	resp, err := http.Get(ts.URL + "/v1/bindings/by-id/bnd_ffffffffffffffffffffffff")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown binding id returned %d, want 404", resp.StatusCode)
	}
}

func mustHexAddr(t *testing.T, s string) [20]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != 20 {
		t.Fatalf("bad address %q", s)
	}
	var out [20]byte
	copy(out[:], b)
	return out
}

// quietTestLogger keeps reconciler output out of test logs unless something
// actually goes wrong.
func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
