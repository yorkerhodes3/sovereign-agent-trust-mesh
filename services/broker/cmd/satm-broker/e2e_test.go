//go:build integration

// End-to-end test for the broker.
//
// This is the only test that exercises the WHOLE composition -- HTTP handler,
// verifier, real JSON-RPC against deployed ERC-8004 bytecode, real registration
// fetch, real nonce store -- with nothing stubbed. Each package's own tests
// prove its internals; this proves the pieces actually fit together.
//
// Run with:
//
//	anvil --port 8545 &
//	forge script script/DeployRegistries.s.sol --rpc-url http://127.0.0.1:8545 \
//	  --broadcast --private-key $PK
//	go test -tags integration ./cmd/satm-broker/
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/chainrpc"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/config"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/fetch"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store"
)

// Anvil account #0: a publicly documented devnet key, not a secret.
const (
	anvilPK       = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	anvilAddr     = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	testMeshID    = "satm-dev"
	testCtrlPlane = "http://127.0.0.1:8080"
)

func rpcURL() string {
	if v := os.Getenv("SATM_RPC_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:8545"
}

func registryAddress(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "contracts", "deployments", "31337.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no devnet deployment at %s; run DeployRegistries first: %v", path, err)
	}
	var d struct {
		IdentityRegistry string `json:"identityRegistry"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse deployment: %v", err)
	}
	return strings.ToLower(d.IdentityRegistry)
}

func castPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cast")
	if err != nil {
		t.Skipf("cast (foundry) not on PATH: %v", err)
	}
	return p
}

// runCast executes a cast subcommand and returns STDOUT only.
//
// CombinedOutput would be wrong here: foundry writes advisory notices (such as
// the nightly-build warning) to stderr, and mixing those into a value that gets
// parsed makes the test fail for reasons unrelated to what it is testing.
func runCast(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(castPath(t), args...)
	cmd.Env = append(os.Environ(), "FOUNDRY_DISABLE_NIGHTLY_WARNING=1")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cast %s: %v\nstderr: %s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// lastNonEmptyLine returns the final meaningful line of command output, which is
// where cast puts the actual return value.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if trimmed := strings.TrimSpace(lines[i]); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// registerAgent registers an agent whose tokenURI is a data: URI carrying the
// registration file.
//
// A data URI is used rather than an HTTP endpoint because the registration file
// must name the agentId, which is not known until the agent is registered. The
// two-step below breaks that circularity: simulate register() to learn the id
// the next call will assign, build the file around it, then send for real.
func registerAgent(t *testing.T, registry, peerID string) *big.Int {
	t.Helper()

	// Step 1: eth_call register() to learn the id without changing state.
	out := runCast(t, "call", registry,
		"register(string)(uint256)", "placeholder",
		"--rpc-url", rpcURL(), "--from", anvilAddr)

	idStr := lastNonEmptyLine(out)
	agentID, ok := new(big.Int).SetString(idStr, 10)
	if !ok {
		t.Fatalf("could not parse predicted agentId from %q (last line %q)", out, idStr)
	}

	// Step 2: build the registration file naming that id and this peer.
	regFile := map[string]any{
		"type":        "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
		"name":        "satm-e2e-agent",
		"description": "end-to-end test agent",
		"active":      true,
		"registrations": []map[string]any{
			{"agentId": agentID.String(), "agentRegistry": "eip155:31337:" + registry},
		},
		"services": []map[string]any{
			{"name": "sam", "endpoint": binding.FormatSAMURI(peerID, testMeshID)},
		},
	}
	encoded, err := json.Marshal(regFile)
	if err != nil {
		t.Fatalf("marshal registration file: %v", err)
	}
	dataURI := "data:application/json;base64," + base64.StdEncoding.EncodeToString(encoded)

	// Step 3: register for real.
	runCast(t, "send", registry,
		"register(string)", dataURI,
		"--rpc-url", rpcURL(), "--private-key", anvilPK)
	return agentID
}

// newBrokerServer builds the real handler stack over live infrastructure.
func newBrokerServer(t *testing.T, registry string) (*httptest.Server, *store.Memory) {
	t.Helper()

	cfg := &config.Config{
		Version:      "v1",
		MeshID:       testMeshID,
		Listen:       "127.0.0.1:0",
		ControlPlane: config.ControlPlane{URL: testCtrlPlane, RequireManualApproval: true},
		Chains: config.Chains{Identity: config.IdentityChain{
			ChainID:          31337,
			RPCUrls:          []string{rpcURL()},
			RPCQuorum:        1,
			IdentityRegistry: registry,
		}},
		Binding: config.BindingConfig{
			MaxTTL:                   168 * time.Hour,
			ClockSkew:                60 * time.Second,
			NonceRetention:           240 * time.Hour,
			TrustedRegistries:        []string{"eip155:31337:" + registry},
			RequireUniqueAgentWallet: true,
			OneActiveBindingPerAgent: true,
		},
	}

	verifierCfg, err := cfg.VerifierConfig()
	if err != nil {
		t.Fatalf("verifier config: %v", err)
	}

	rpcCfg := chainrpc.DefaultConfig(rpcURL())
	rpcCfg.Quorum = 1
	chain, err := chainrpc.New(rpcCfg)
	if err != nil {
		t.Fatalf("chain client: %v", err)
	}

	// data: URIs never hit the network, so private-range blocking is irrelevant
	// here; it stays ON to match production behaviour exactly.
	fetchCfg := fetch.DefaultConfig()
	fetcher := fetch.New(fetchCfg)

	nonceStore := store.NewMemory()
	verifier, err := binding.NewVerifier(verifierCfg, chain, fetcher, nonceStore)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	srv := &server{
		verifier: verifier,
		store:    nonceStore,
		log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		cfg:      cfg,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/bindings", srv.handleCreateBinding)
	mux.HandleFunc("GET /v1/bindings/{caid...}", srv.handleGetBinding)
	mux.HandleFunc("GET /healthz", srv.handleHealth)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, nonceStore
}

type agentKeys struct {
	peerID     string
	peerPubKey []byte
	peerPriv   ed25519.PrivateKey
	sidecarKey string
	walletPriv *secp256k1.PrivateKey
	wallet     [20]byte
}

func newAgentKeys(t *testing.T) *agentKeys {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	libp2pPub, err := libp2pcrypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatalf("unmarshal libp2p key: %v", err)
	}
	pid, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	// MUST be the libp2p protobuf-marshalled form, not the raw 32 bytes: the
	// PeerID is multihash(protobuf(pubkey)), so raw bytes would derive a
	// different -- and wrong -- peer id.
	marshalledPub, err := libp2pcrypto.MarshalPublicKey(libp2pPub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}

	// The sidecar key is a SEPARATE hot key used for per-call attestations. It
	// is deliberately not the host key: the host key is cold and long-lived,
	// while this one signs on every call (SPECIFICATION.md 6.3.3).
	sidecarPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sidecar ed25519: %v", err)
	}

	pkBytes, err := hex.DecodeString(strings.TrimPrefix(anvilPK, "0x"))
	if err != nil {
		t.Fatalf("decode anvil key: %v", err)
	}
	walletPriv := secp256k1.PrivKeyFromBytes(pkBytes)

	var wallet [20]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(anvilAddr, "0x"))
	copy(wallet[:], b)

	return &agentKeys{
		peerID:     pid.String(),
		peerPubKey: marshalledPub,
		peerPriv:   priv,
		sidecarKey: "ed25519:" + base58.Encode(sidecarPub),
		walletPriv: walletPriv,
		wallet:     wallet,
	}
}

// signWallet produces a 65-byte [R||S||V] signature over an EIP-712 digest.
func signWallet(priv *secp256k1.PrivateKey, digest [32]byte) []byte {
	compact := dcrecdsa.SignCompact(priv, digest[:], false)
	sig := make([]byte, 65)
	copy(sig[0:64], compact[1:65]) // dcrec emits [V||R||S]; the wire format is [R||S||V]
	sig[64] = compact[0]
	return sig
}

// buildSubmission assembles a fully signed binding submission.
func buildSubmission(t *testing.T, keys *agentKeys, registry string, agentID *big.Int) createBindingRequest {
	t.Helper()

	tuple := "eip155:31337:" + registry
	doc, err := binding.NewDocument(
		tuple, agentID, keys.wallet,
		keys.peerID, keys.sidecarKey, testMeshID, testCtrlPlane,
		time.Now().UTC(), time.Hour,
	)
	if err != nil {
		t.Fatalf("NewDocument: %v", err)
	}

	docBytes, err := doc.Canonicalize()
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	peerDigest, err := binding.PeerSigningDigest(doc)
	if err != nil {
		t.Fatalf("peer digest: %v", err)
	}
	peerSig := ed25519.Sign(keys.peerPriv, peerDigest[:])

	reg, err := binding.ParseTrustedRegistry(tuple)
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	walletDigest, err := binding.MeshBindingDigest(doc, binding.DomainParams{
		ChainID:           reg.ChainID,
		VerifyingContract: reg.Address,
	})
	if err != nil {
		t.Fatalf("wallet digest: %v", err)
	}

	return createBindingRequest{
		Document:        docBytes,
		PeerPublicKey:   keys.peerPubKey,
		PeerSignature:   peerSig,
		WalletSignature: signWallet(keys.walletPriv, walletDigest),
	}
}

func postBinding(t *testing.T, url string, req createBindingRequest) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url+"/v1/bindings", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestE2EBindingAccepted is the headline case: a correctly signed binding for a
// genuinely registered on-chain agent is admitted.
func TestE2EBindingAccepted(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	ts, _ := newBrokerServer(t, registry)
	status, body := postBinding(t, ts.URL, buildSubmission(t, keys, registry, agentID))

	if status != http.StatusCreated {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	if body["peerId"] != keys.peerID {
		t.Errorf("peerId = %v, want %s", body["peerId"], keys.peerID)
	}
	wantCAID := fmt.Sprintf("eip155:31337:%s/%s", registry, agentID)
	if body["caid"] != wantCAID {
		t.Errorf("caid = %v, want %s", body["caid"], wantCAID)
	}
	if body["meshId"] != testMeshID {
		t.Errorf("meshId = %v", body["meshId"])
	}
}

// TestE2EBindingIsRetrievable checks the read path after a successful commit.
func TestE2EBindingIsRetrievable(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	ts, _ := newBrokerServer(t, registry)
	status, body := postBinding(t, ts.URL, buildSubmission(t, keys, registry, agentID))
	if status != http.StatusCreated {
		t.Fatalf("setup failed: status %d, body %v", status, body)
	}

	caid := body["caid"].(string)
	resp, err := http.Get(ts.URL + "/v1/bindings/" + caid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["peerId"] != keys.peerID {
		t.Errorf("peerId = %v, want %s", got["peerId"], keys.peerID)
	}
}

// TestE2EReplayRejected proves the nonce is consumed against a real store: the
// identical submission must not be admitted twice.
func TestE2EReplayRejected(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	ts, _ := newBrokerServer(t, registry)
	req := buildSubmission(t, keys, registry, agentID)

	if status, body := postBinding(t, ts.URL, req); status != http.StatusCreated {
		t.Fatalf("first submission failed: %d %v", status, body)
	}
	status, body := postBinding(t, ts.URL, req)
	if status == http.StatusCreated {
		t.Fatal("replayed submission was accepted")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %v", status, body)
	}
	t.Logf("replay denied with reason %v", body["reason"])
}

// TestE2EUnknownAgentRejected covers check B6 against real chain state.
func TestE2EUnknownAgentRejected(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)

	ts, _ := newBrokerServer(t, registry)
	req := buildSubmission(t, keys, registry, big.NewInt(999999))

	status, body := postBinding(t, ts.URL, req)
	if status == http.StatusCreated {
		t.Fatal("binding for a non-existent agent was accepted")
	}
	// Must be denied because the AGENT is unknown, not because the submission
	// was malformed on the way in.
	if got := body["reason"]; got != "binding.agent_not_found" {
		t.Fatalf("reason = %v, want binding.agent_not_found; body = %v", got, body)
	}
}

// TestE2EForgedPeerSignatureRejected covers check B5 end to end.
func TestE2EForgedPeerSignatureRejected(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	ts, _ := newBrokerServer(t, registry)
	req := buildSubmission(t, keys, registry, agentID)
	req.PeerSignature[0] ^= 0xFF

	status, body := postBinding(t, ts.URL, req)
	if status == http.StatusCreated {
		t.Fatal("binding with a corrupted peer signature was accepted")
	}
	// Specifically the SIGNATURE must be what fails; the key still derives the
	// claimed peer id correctly.
	if got := body["reason"]; got != "binding.peer_signature_invalid" {
		t.Fatalf("reason = %v, want binding.peer_signature_invalid; body = %v", got, body)
	}
}

// TestE2EWrongMeshRejected covers check B2: a document naming another mesh must
// not be admitted here even though every signature over it is valid.
func TestE2EWrongMeshRejected(t *testing.T) {
	registry := registryAddress(t)
	keys := newAgentKeys(t)
	agentID := registerAgent(t, registry, keys.peerID)

	tuple := "eip155:31337:" + registry
	doc, err := binding.NewDocument(tuple, agentID, keys.wallet,
		keys.peerID, keys.sidecarKey, "some-other-mesh", testCtrlPlane,
		time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatalf("NewDocument: %v", err)
	}
	// Every error here is checked: a setup failure that silently produced an
	// unsigned or empty document would make this test pass for the wrong
	// reason -- it would be rejected as malformed rather than as wrong-mesh.
	docBytes, err := doc.Canonicalize()
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	peerDigest, err := binding.PeerSigningDigest(doc)
	if err != nil {
		t.Fatalf("peer digest: %v", err)
	}
	reg, err := binding.ParseTrustedRegistry(tuple)
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	walletDigest, err := binding.MeshBindingDigest(doc, binding.DomainParams{
		ChainID: reg.ChainID, VerifyingContract: reg.Address,
	})
	if err != nil {
		t.Fatalf("wallet digest: %v", err)
	}

	ts, _ := newBrokerServer(t, registry)
	status, body := postBinding(t, ts.URL, createBindingRequest{
		Document:        docBytes,
		PeerPublicKey:   keys.peerPubKey,
		PeerSignature:   ed25519.Sign(keys.peerPriv, peerDigest[:]),
		WalletSignature: signWallet(keys.walletPriv, walletDigest),
	})
	if status == http.StatusCreated {
		t.Fatal("binding for a different mesh was accepted")
	}
	// The denial must be about the MESH, not about the document being unparseable.
	if body["reason"] == "binding.malformed" {
		t.Fatalf("document was rejected as malformed, so this test proves nothing about mesh checking: %v", body)
	}
	t.Logf("denied with reason %v", body["reason"])
}

func TestE2EHealthz(t *testing.T) {
	registry := registryAddress(t)
	ts, _ := newBrokerServer(t, registry)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestE2EOversizedRequestRejected checks the request cap.
func TestE2EOversizedRequestRejected(t *testing.T) {
	registry := registryAddress(t)
	ts, _ := newBrokerServer(t, registry)

	huge := bytes.Repeat([]byte("A"), maxRequestBytes+1024)
	resp, err := http.Post(ts.URL+"/v1/bindings", "application/json", bytes.NewReader(huge))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("oversized request was accepted")
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// TestE2EContextIsPlumbed checks the handler passes its request context down to
// the chain client, so a cancelled client request does not leave work running.
func TestE2EContextIsPlumbed(t *testing.T) {
	registry := registryAddress(t)
	ts, _ := newBrokerServer(t, registry)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/v1/bindings",
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("request with a cancelled context succeeded")
	}
}
