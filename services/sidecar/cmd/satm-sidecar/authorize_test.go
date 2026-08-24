package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/internal/attest"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/sidecar/internal/trustapi"
)

// Real libp2p-derived peer ids, so the fixtures exercise the same validation a
// production document would.
const (
	testMesh   = "satm-dev"
	testCP     = "http://127.0.0.1:8080"
	callerCAID = "eip155:31337:0x1111111111111111111111111111111111111111/7"
	targetCAID = "eip155:31337:0x1111111111111111111111111111111111111111/42"
	callerPeer = "12D3KooWRqNk4qxTyDgr6WGxY3KH8jW83HKRPpTK43AmASimnLz3"
	targetPeer = "12D3KooWMg6u9dcdLMDwM2KKYueV3G5k55DP1ow82kBXebs1F1v1"
	callerBnd  = "bnd_aaaaaaaaaaaaaaaaaaaaaaaa"
	targetBnd  = "bnd_bbbbbbbbbbbbbbbbbbbbbbbb"
)

type harness struct {
	t          *testing.T
	ts         *httptest.Server
	callerPriv ed25519.PrivateKey
	brokerHits int
	active     bool
}

// newHarness wires a real sidecar server against a stub broker Trust API.
func newHarness(t *testing.T) *harness {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	h := &harness{t: t, callerPriv: priv, active: true}

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.brokerHits++
		if r.URL.Path != "/v1/bindings/by-id/"+callerBnd {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         callerBnd,
			"caid":       callerCAID,
			"peerId":     callerPeer,
			"meshId":     testMesh,
			"sidecarKey": base64.RawURLEncoding.EncodeToString(pub),
			"active":     h.active,
		})
	}))
	t.Cleanup(broker.Close)

	cfg := trustapi.DefaultConfig(broker.URL)
	cfg.CacheTTL = 0 // no caching in tests; freshness is asserted directly
	trust, err := trustapi.New(cfg)
	if err != nil {
		t.Fatalf("trustapi: %v", err)
	}

	store := attest.NewMemoryNonceStore()
	verifier, err := attest.NewVerifier(attest.Config{
		MeshID:       testMesh,
		ControlPlane: testCP,
		Self:         attest.SelfFromBinding(targetCAID, targetPeer, targetBnd),
		TTL:          30 * time.Second,
		ClockSkew:    5 * time.Second,
	}, trust, store)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	srv := &server{
		verifier: verifier,
		trust:    trust,
		store:    store,
		self:     attest.SelfFromBinding(targetCAID, targetPeer, targetBnd),
		meshID:   testMesh,
		cp:       testCP,
		ttl:      30 * time.Second,
		log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/authorize", srv.handleAuthorize)
	mux.HandleFunc("GET /healthz", srv.handleHealth)

	h.ts = httptest.NewServer(mux)
	t.Cleanup(h.ts.Close)
	return h
}

func (h *harness) attestation(service, tool string, args map[string]any) string {
	h.t.Helper()
	argsHash, err := attest.HashArgs(args)
	if err != nil {
		h.t.Fatalf("HashArgs: %v", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		h.t.Fatalf("rand: %v", err)
	}
	now := time.Now().UTC()

	doc := &attest.Document{
		Type:            attest.DocumentType,
		MeshID:          testMesh,
		ControlPlane:    testCP,
		CallerCAID:      callerCAID,
		CallerPeerID:    callerPeer,
		CallerBindingID: callerBnd,
		TargetCAID:      targetCAID,
		TargetPeerID:    targetPeer,
		TargetBindingID: targetBnd,
		Service:         service,
		Tool:            tool,
		ArgsHash:        argsHash,
		Nonce:           base64.RawURLEncoding.EncodeToString(nonce[:]),
		IssuedAt:        now.Format(time.RFC3339),
		ExpiresAt:       now.Add(30 * time.Second).Format(time.RFC3339),
	}
	env, err := attest.Sign(doc, h.callerPriv)
	if err != nil {
		h.t.Fatalf("Sign: %v", err)
	}
	encoded, err := env.Marshal()
	if err != nil {
		h.t.Fatalf("Marshal: %v", err)
	}
	return encoded
}

func (h *harness) post(body string) (int, map[string]any) {
	h.t.Helper()
	resp, err := http.Post(h.ts.URL+"/v1/authorize", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		h.t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// ------------------------------------------------------------- inbound ----

func TestInboundAllowsValidAttestation(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}

	status, body := h.post(mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{"attestation": h.attestation("mcp://custody", "quote_treasury_note", args)},
		"call": map[string]any{
			"service": "mcp://custody", "tool": "quote_treasury_note", "args": args,
		},
	}))

	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	if body["allow"] != true {
		t.Fatalf("allow = %v, want true", body["allow"])
	}
	// The caller identity must come from the attestation, not be echoed from
	// anything the request asserted.
	if body["callerCaid"] != callerCAID {
		t.Fatalf("callerCaid = %v, want %s", body["callerCaid"], callerCAID)
	}
}

// TestInboundRejectsSelfDeclaredCallerIdentity is threat TH-7a at the HTTP
// boundary: a caller must not be able to name who it is.
func TestInboundRejectsSelfDeclaredCallerIdentity(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}
	att := h.attestation("mcp://custody", "quote_treasury_note", args)

	// A `self` field is not in the schema at all. Unknown-field rejection makes
	// the attempt fail loudly rather than being silently ignored.
	body := `{"direction":"inbound","self":{"caid":"` + callerCAID + `"},` +
		`"peer":{"attestation":"` + att + `"},` +
		`"call":{"service":"mcp://custody","tool":"quote_treasury_note","args":{"isin":"US0000001"}}}`

	status, resp := h.post(body)
	if status == http.StatusOK {
		t.Fatal("a request carrying a self-declared identity was accepted")
	}
	if resp["reason"] != "malformed" {
		t.Fatalf("reason = %v, want malformed; body = %v", resp["reason"], resp)
	}
}

// TestInboundRejectsPeerIdField is the other half of schema separation: the
// inbound path must not accept an unauthenticated peer id.
func TestInboundRejectsPeerIdField(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}

	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer": map[string]any{
			"peerId":      callerPeer,
			"attestation": h.attestation("mcp://custody", "quote_treasury_note", args),
		},
		"call": map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note", "args": args},
	}))

	if status == http.StatusOK {
		t.Fatal("inbound accepted a peer.peerId; caller identity must come from the attestation alone")
	}
	if resp["reason"] != "malformed" {
		t.Fatalf("reason = %v, want malformed", resp["reason"])
	}
}

func TestInboundRequiresAttestation(t *testing.T) {
	h := newHarness(t)
	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{},
		"call":      map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note"},
	}))
	if status == http.StatusOK {
		t.Fatal("inbound without an attestation was allowed")
	}
	if resp["reason"] != "malformed" {
		t.Fatalf("reason = %v", resp["reason"])
	}
}

// TestInboundRejectsToolEscalation is check V3 exercised over HTTP: a genuine
// attestation for a read tool presented against an asset-moving tool.
func TestInboundRejectsToolEscalation(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}
	att := h.attestation("mcp://custody", "quote_treasury_note", args)

	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{"attestation": att},
		"call": map[string]any{
			"service": "mcp://custody", "tool": "subscribe_treasury_note", "args": args,
		},
	}))

	if status == http.StatusOK {
		t.Fatal("a quote attestation authorised a subscribe call")
	}
	if resp["reason"] != string(attest.ReasonWrongTool) {
		t.Fatalf("reason = %v, want %s", resp["reason"], attest.ReasonWrongTool)
	}
}

func TestInboundRejectsMutatedArgs(t *testing.T) {
	h := newHarness(t)
	att := h.attestation("mcp://custody", "quote_treasury_note", map[string]any{"amount": "1000"})

	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{"attestation": att},
		"call": map[string]any{
			"service": "mcp://custody", "tool": "quote_treasury_note",
			"args": map[string]any{"amount": "999999999"},
		},
	}))

	if status == http.StatusOK {
		t.Fatal("mutated arguments were accepted")
	}
	if resp["reason"] != string(attest.ReasonArgsMismatch) {
		t.Fatalf("reason = %v, want %s", resp["reason"], attest.ReasonArgsMismatch)
	}
}

func TestInboundRejectsReplay(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}
	att := h.attestation("mcp://custody", "quote_treasury_note", args)

	req := mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{"attestation": att},
		"call":      map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note", "args": args},
	})

	if status, body := h.post(req); status != http.StatusOK {
		t.Fatalf("first call: status %d, body %v", status, body)
	}
	status, resp := h.post(req)
	if status == http.StatusOK {
		t.Fatal("replayed attestation was accepted")
	}
	if resp["reason"] != string(attest.ReasonNonceReused) {
		t.Fatalf("reason = %v, want %s", resp["reason"], attest.ReasonNonceReused)
	}
}

// TestInboundRejectsRevokedCallerBinding proves revocation propagates: once the
// broker marks the caller's binding inactive, its outstanding attestations stop
// working.
func TestInboundRejectsRevokedCallerBinding(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}
	att := h.attestation("mcp://custody", "quote_treasury_note", args)

	h.active = false // the caller re-bound or was revoked

	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{"attestation": att},
		"call":      map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note", "args": args},
	}))

	if status == http.StatusOK {
		t.Fatal("an attestation from a revoked binding was accepted")
	}
	if resp["reason"] != string(attest.ReasonBindingSuperseded) {
		t.Fatalf("reason = %v, want %s", resp["reason"], attest.ReasonBindingSuperseded)
	}
}

// TestInboundBrokerOutageReturns503 keeps an infrastructure failure
// distinguishable from a denial, including in the HTTP status.
func TestInboundBrokerOutageReturns503(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}
	att := h.attestation("mcp://custody", "quote_treasury_note", args)

	// Point the verifier at a dead broker.
	cfg := trustapi.DefaultConfig("http://127.0.0.1:1")
	cfg.Timeout = 200 * time.Millisecond
	cfg.CacheTTL = 0
	dead, err := trustapi.New(cfg)
	if err != nil {
		t.Fatalf("trustapi: %v", err)
	}
	verifier, err := attest.NewVerifier(attest.Config{
		MeshID: testMesh, ControlPlane: testCP,
		Self: attest.SelfFromBinding(targetCAID, targetPeer, targetBnd),
		TTL:  30 * time.Second, ClockSkew: 5 * time.Second,
	}, dead, attest.NewMemoryNonceStore())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	srv := &server{
		verifier: verifier, trust: dead, store: attest.NewMemoryNonceStore(),
		self:   attest.SelfFromBinding(targetCAID, targetPeer, targetBnd),
		meshID: testMesh, cp: testCP, ttl: 30 * time.Second,
		log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/authorize", srv.handleAuthorize)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := mustJSON(t, map[string]any{
		"direction": "inbound",
		"peer":      map[string]any{"attestation": att},
		"call":      map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note", "args": args},
	})
	resp, err := http.Post(ts.URL+"/v1/authorize", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for a broker outage", resp.StatusCode)
	}
}

// ------------------------------------------------------------ outbound ----

// TestOutboundRejectsAttestationInput pins the schema asymmetry the
// specification calls out: requiring an attestation on the outbound path is
// impossible, because the attestation is an OUTPUT of authorization.
func TestOutboundRejectsAttestationInput(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{"isin": "US0000001"}

	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "outbound",
		"peer": map[string]any{
			"peerId":      targetPeer,
			"attestation": h.attestation("mcp://custody", "quote_treasury_note", args),
		},
		"call": map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note", "args": args},
	}))

	if status == http.StatusOK {
		t.Fatal("outbound accepted an attestation as input")
	}
	if resp["reason"] != "malformed" {
		t.Fatalf("reason = %v, want malformed", resp["reason"])
	}
}

func TestOutboundRequiresPeerID(t *testing.T) {
	h := newHarness(t)
	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "outbound",
		"peer":      map[string]any{},
		"call":      map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note"},
	}))
	if status == http.StatusOK {
		t.Fatal("outbound without a peerId was allowed")
	}
	if resp["reason"] != "malformed" {
		t.Fatalf("reason = %v", resp["reason"])
	}
}

// TestOutboundIsHonestlyUnimplemented asserts the incomplete path fails closed
// with a distinct, findable reason rather than inventing an allow.
func TestOutboundIsHonestlyUnimplemented(t *testing.T) {
	h := newHarness(t)
	status, resp := h.post(mustJSON(t, map[string]any{
		"direction": "outbound",
		"peer":      map[string]any{"peerId": targetPeer},
		"call":      map[string]any{"service": "mcp://custody", "tool": "quote_treasury_note"},
	}))

	if status == http.StatusOK || resp["allow"] == true {
		t.Fatal("an unimplemented path returned an allow")
	}
	if status != http.StatusNotImplemented && status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 501 or 503", status)
	}
}

// -------------------------------------------------------------- general ---

func TestRejectsUnknownDirection(t *testing.T) {
	h := newHarness(t)
	for _, d := range []string{"", "sideways", "INBOUND"} {
		status, _ := h.post(mustJSON(t, map[string]any{
			"direction": d,
			"peer":      map[string]any{},
			"call":      map[string]any{},
		}))
		if status == http.StatusOK {
			t.Errorf("direction %q was accepted", d)
		}
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	h := newHarness(t)
	huge := bytes.Repeat([]byte("A"), maxRequestBytes+1024)
	resp, err := http.Post(h.ts.URL+"/v1/authorize", "application/json", bytes.NewReader(huge))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	checks, ok := body["checks"].([]any)
	if !ok || len(checks) != 8 {
		t.Fatalf("healthz should advertise all 8 attestation checks, got %v", body["checks"])
	}
}

func TestContextIsPlumbed(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.ts.URL+"/v1/authorize",
		bytes.NewReader([]byte(`{"direction":"inbound","peer":{},"call":{}}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("request with a cancelled context succeeded")
	}
}
