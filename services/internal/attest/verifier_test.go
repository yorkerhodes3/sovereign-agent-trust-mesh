package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fixture --

const (
	testMesh         = "satm-dev"
	testControlPlane = "http://127.0.0.1:8080"

	callerCAID = "eip155:31337:0x1111111111111111111111111111111111111111/7"
	targetCAID = "eip155:31337:0x1111111111111111111111111111111111111111/42"

	callerPeer = "12D3KooWRqNk4qxTyDgr6WGxY3KH8jW83HKRPpTK43AmASimnLz3"
	targetPeer = "12D3KooWMg6u9dcdLMDwM2KKYueV3G5k55DP1ow82kBXebs1F1v1"

	callerBindingID = "bnd_aaaaaaaaaaaaaaaaaaaaaaaa"
	targetBindingID = "bnd_bbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeTrustAPI is a simple in-memory Trust API. Not a mock with call-order
// expectations: the tests assert on VERIFIER behaviour, and coupling them to
// internals would make legitimate refactors look like failures.
type fakeTrustAPI struct {
	bindings map[string]*CallerBinding
	err      error
}

func (f *fakeTrustAPI) BindingByID(_ context.Context, id string) (*CallerBinding, error) {
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	return b, nil
}

type fixture struct {
	t          *testing.T
	verifier   *Verifier
	trust      *fakeTrustAPI
	store      *MemoryNonceStore
	callerPriv ed25519.PrivateKey
	callerPub  ed25519.PublicKey
	now        time.Time
	req        Request
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	trust := &fakeTrustAPI{bindings: map[string]*CallerBinding{
		callerBindingID: {
			BindingID:  callerBindingID,
			CAID:       callerCAID,
			PeerID:     callerPeer,
			SidecarKey: pub,
			Active:     true,
		},
	}}
	store := NewMemoryNonceStore()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	f := &fixture{
		t:          t,
		trust:      trust,
		store:      store,
		callerPriv: priv,
		callerPub:  pub,
		now:        now,
		req: Request{
			Service: "mcp://custody",
			Tool:    "quote_treasury_note",
			Args:    map[string]any{"isin": "US0000001", "amount": "1000"},
		},
	}

	v, err := NewVerifier(Config{
		MeshID:       testMesh,
		ControlPlane: testControlPlane,
		Self:         SelfFromBinding(targetCAID, targetPeer, targetBindingID),
		TTL:          30 * time.Second,
		ClockSkew:    5 * time.Second,
		Now:          func() time.Time { return f.now },
	}, trust, store)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	f.verifier = v
	return f
}

// doc builds a well-formed attestation matching the fixture's request.
func (f *fixture) doc() *Document {
	f.t.Helper()
	argsHash, err := HashArgs(f.req.Args)
	if err != nil {
		f.t.Fatalf("HashArgs: %v", err)
	}
	return &Document{
		Type:            DocumentType,
		MeshID:          testMesh,
		ControlPlane:    testControlPlane,
		CallerCAID:      callerCAID,
		CallerPeerID:    callerPeer,
		CallerBindingID: callerBindingID,
		TargetCAID:      targetCAID,
		TargetPeerID:    targetPeer,
		TargetBindingID: targetBindingID,
		Service:         f.req.Service,
		Tool:            f.req.Tool,
		ArgsHash:        argsHash,
		Nonce:           newTestNonce(f.t),
		IssuedAt:        f.now.Format(time.RFC3339),
		ExpiresAt:       f.now.Add(30 * time.Second).Format(time.RFC3339),
	}
}

func (f *fixture) sign(doc *Document) *Envelope {
	f.t.Helper()
	env, err := Sign(doc, f.callerPriv)
	if err != nil {
		f.t.Fatalf("Sign: %v", err)
	}
	return env
}

// signUnchecked signs without the structural validation Sign performs.
//
// Needed to build documents a conforming client would refuse to produce. An
// attacker has no obligation to use our signer, so tests for structural checks
// must be able to construct the hostile input directly -- otherwise they only
// prove that our own signer is careful, which is not the property under test.
func (f *fixture) signUnchecked(doc *Document) *Envelope {
	f.t.Helper()
	digest, err := doc.SigningDigest()
	if err != nil {
		f.t.Fatalf("SigningDigest: %v", err)
	}
	sig := ed25519.Sign(f.callerPriv, digest[:])
	return &Envelope{
		Document:  doc,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func (f *fixture) verify(env *Envelope) (*Result, error) {
	return f.verifier.Verify(context.Background(), env, f.req)
}

// verifyDoc signs and verifies in one step, for the common case.
func (f *fixture) verifyDoc(doc *Document) (*Result, error) {
	return f.verify(f.sign(doc))
}

func newTestNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func assertDenied(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected denial %q, got success", want)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *attest.Error, got %T: %v", err, err)
	}
	if e.Reason != want {
		t.Fatalf("expected reason %q, got %q (check %s: %v)", want, e.Reason, e.Check, err)
	}
}

// ------------------------------------------------------------ happy path --

func TestVerify_ValidAttestationSucceeds(t *testing.T) {
	f := newFixture(t)
	res, err := f.verifyDoc(f.doc())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Caller.CAID != callerCAID {
		t.Fatalf("caller CAID = %q, want %q", res.Caller.CAID, callerCAID)
	}
}

func TestNewVerifier_RejectsIncompleteSelf(t *testing.T) {
	base := Config{
		MeshID:       testMesh,
		ControlPlane: testControlPlane,
		TTL:          30 * time.Second,
	}
	trust := &fakeTrustAPI{bindings: map[string]*CallerBinding{}}
	store := NewMemoryNonceStore()

	cases := map[string]Self{
		"no caid":      {PeerID: targetPeer, BindingID: targetBindingID},
		"no peer":      {CAID: targetCAID, BindingID: targetBindingID},
		"no bindingId": {CAID: targetCAID, PeerID: targetPeer},
		"empty":        {},
	}
	for name, self := range cases {
		cfg := base
		cfg.Self = self
		if _, err := NewVerifier(cfg, trust, store); err == nil {
			t.Errorf("%s: incomplete self was accepted; V2 could not be enforced", name)
		}
	}
}

func TestNewVerifier_RequiresPorts(t *testing.T) {
	cfg := Config{
		MeshID:       testMesh,
		ControlPlane: testControlPlane,
		Self:         SelfFromBinding(targetCAID, targetPeer, targetBindingID),
		TTL:          30 * time.Second,
	}
	if _, err := NewVerifier(cfg, nil, NewMemoryNonceStore()); err == nil {
		t.Error("nil TrustAPI was accepted")
	}
	if _, err := NewVerifier(cfg, &fakeTrustAPI{}, nil); err == nil {
		t.Error("nil NonceStore was accepted; V8 could not be enforced")
	}
	cfg.TTL = 0
	if _, err := NewVerifier(cfg, &fakeTrustAPI{}, NewMemoryNonceStore()); err == nil {
		t.Error("zero TTL was accepted")
	}
}

// ------------------------------------------------------------------- V1 ---

func TestVerify_V1_RejectsWrongMesh(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.MeshID = "some-other-mesh"
	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonWrongMesh)
}

func TestVerify_V1_RejectsWrongControlPlane(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.ControlPlane = "http://attacker.example"
	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonWrongControlPlane)
}

// ------------------------------------------------------------------- V2 ---

// TestVerify_V2_RejectsReplayAtDifferentCallee is the core TH-7a case: an
// attestation captured in transit must not work anywhere else.
func TestVerify_V2_RejectsReplayAtDifferentCallee(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.TargetCAID = "eip155:31337:0x1111111111111111111111111111111111111111/99"
	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonWrongTarget)
}

func TestVerify_V2_RejectsWrongTargetPeer(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.TargetPeerID = "12D3KooWRGyuZjTiZ2sWmrcdqgCzbf5eaWZC71Wi419g7UvFsSxD"
	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonWrongTarget)
}

// TestVerify_V2_RejectsAttestationForSupersededSelfBinding proves the responder
// side of key-epoch revocation: after this agent re-binds, attestations issued
// against its previous binding stop working.
func TestVerify_V2_RejectsAttestationForSupersededSelfBinding(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.TargetBindingID = "bnd_cccccccccccccccccccccccc"
	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonWrongTarget)
}

// ------------------------------------------------------------------- V3 ---

// TestVerify_V3_RejectsToolEscalation is the check the specification calls out
// as "not optional": a cheap attestation for a read tool must not be presentable
// to an asset-moving tool.
func TestVerify_V3_RejectsToolEscalation(t *testing.T) {
	f := newFixture(t)

	// The caller legitimately obtains an attestation for the read-only quote
	// tool, then presents it against the asset-moving subscribe tool.
	doc := f.doc()
	env := f.sign(doc)

	f.req.Tool = "subscribe_treasury_note"
	_, err := f.verifier.Verify(context.Background(), env, f.req)
	assertDenied(t, err, ReasonWrongTool)
}

func TestVerify_V3_RejectsWrongService(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	env := f.sign(doc)

	f.req.Service = "mcp://payments"
	_, err := f.verifier.Verify(context.Background(), env, f.req)
	assertDenied(t, err, ReasonWrongService)
}

// ------------------------------------------------------------------- V4 ---

// TestVerify_V4_RejectsMutatedArguments covers body substitution: a genuine
// attestation with the payload swapped underneath it.
func TestVerify_V4_RejectsMutatedArguments(t *testing.T) {
	f := newFixture(t)
	env := f.sign(f.doc())

	f.req.Args = map[string]any{"isin": "US0000001", "amount": "999999999"}
	_, err := f.verifier.Verify(context.Background(), env, f.req)
	assertDenied(t, err, ReasonArgsMismatch)
}

func TestVerify_V4_RejectsAddedArgument(t *testing.T) {
	f := newFixture(t)
	env := f.sign(f.doc())

	f.req.Args = map[string]any{"isin": "US0000001", "amount": "1000", "override": true}
	_, err := f.verifier.Verify(context.Background(), env, f.req)
	assertDenied(t, err, ReasonArgsMismatch)
}

// TestVerify_V4_ArgumentOrderIsIrrelevant confirms the check keys on VALUE, not
// on incidental encoding. A false denial here would be as damaging as a false
// accept, because it would push operators to disable the check.
func TestVerify_V4_ArgumentOrderIsIrrelevant(t *testing.T) {
	f := newFixture(t)
	env := f.sign(f.doc())

	// Same pairs, rebuilt in a different insertion order.
	f.req.Args = map[string]any{"amount": "1000", "isin": "US0000001"}
	if _, err := f.verifier.Verify(context.Background(), env, f.req); err != nil {
		t.Fatalf("argument order changed the hash: %v", err)
	}
}

func TestHashArgs_NilAndEmptyAgree(t *testing.T) {
	a, err := HashArgs(nil)
	if err != nil {
		t.Fatalf("HashArgs(nil): %v", err)
	}
	b, err := HashArgs(map[string]any{})
	if err != nil {
		t.Fatalf("HashArgs(empty): %v", err)
	}
	if a != b {
		t.Fatalf("nil and empty args hashed differently: %s vs %s", a, b)
	}
}

func TestHashArgs_IsLowercaseHex(t *testing.T) {
	h, err := HashArgs(map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("HashArgs: %v", err)
	}
	if !strings.HasPrefix(h, "0x") || len(h) != 66 {
		t.Fatalf("argsHash %q is not 0x + 64 hex chars", h)
	}
	if h != strings.ToLower(h) {
		t.Fatalf("argsHash %q is not lowercase", h)
	}
}

// ------------------------------------------------------------------- V5 ---

func TestVerify_V5_RejectsUnknownCallerBinding(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.CallerBindingID = "bnd_dddddddddddddddddddddddd"
	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonUnknownCallerBinding)
}

// TestVerify_V5_RejectsForgedSignature covers the impostor who knows every
// public field but does not hold the sidecar key.
func TestVerify_V5_RejectsForgedSignature(t *testing.T) {
	f := newFixture(t)

	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	doc := f.doc()
	env, err := Sign(doc, attackerPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = f.verify(env)
	assertDenied(t, err, ReasonBadSignature)
}

// TestVerify_V5_SignatureDoesNotSurviveMutation proves the signature actually
// covers the whole document rather than a subset of fields.
func TestVerify_V5_SignatureDoesNotSurviveMutation(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	env := f.sign(doc)

	// Mutate a field AFTER signing. It is still consistent with the request, so
	// V1-V4 pass; only the signature can catch it.
	env.Document.CallerCAID = "eip155:31337:0x1111111111111111111111111111111111111111/8"

	_, err := f.verify(env)
	assertDenied(t, err, ReasonBadSignature)
}

func TestVerify_V5_RejectsMalformedSignature(t *testing.T) {
	f := newFixture(t)
	for name, sig := range map[string]string{
		"not base64url": "!!!!not-base64!!!!",
		"too short":     base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02}),
		"empty":         "",
	} {
		env := f.sign(f.doc())
		env.Signature = sig
		_, err := f.verify(env)
		if err == nil {
			t.Errorf("%s: malformed signature was accepted", name)
			continue
		}
		assertDenied(t, err, ReasonBadSignature)
	}
}

// TestVerify_V5_TrustAPIOutageIsNotADenial keeps an infrastructure failure
// distinguishable from a verdict. Conflating them would train operators to
// ignore denials during an outage.
func TestVerify_V5_TrustAPIOutageIsNotADenial(t *testing.T) {
	f := newFixture(t)
	f.trust.err = errors.New("connection refused")

	_, err := f.verifyDoc(f.doc())
	assertDenied(t, err, ReasonTrustAPIUnavailable)
}

// ------------------------------------------------------------------- V6 ---

// TestVerify_V6_RejectsSupersededCallerBinding is what makes the sidecar key
// revocable: re-binding the caller invalidates every outstanding attestation
// signed under the old key, without any key-revocation list.
func TestVerify_V6_RejectsSupersededCallerBinding(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	env := f.sign(doc)

	// The caller re-binds; the broker marks the old binding inactive.
	f.trust.bindings[callerBindingID].Active = false

	_, err := f.verify(env)
	assertDenied(t, err, ReasonBindingSuperseded)
}

// TestVerify_V6_RejectsCAIDNotMatchingBinding covers a caller who holds a valid
// sidecar key but claims to be a different agent with it.
func TestVerify_V6_RejectsCAIDNotMatchingBinding(t *testing.T) {
	f := newFixture(t)
	// The binding record says agent /7; the attestation claims /9.
	f.trust.bindings[callerBindingID].CAID =
		"eip155:31337:0x1111111111111111111111111111111111111111/9"

	_, err := f.verifyDoc(f.doc())
	assertDenied(t, err, ReasonCallerPeerMismatch)
}

func TestVerify_V6_RejectsPeerNotMatchingBinding(t *testing.T) {
	f := newFixture(t)
	f.trust.bindings[callerBindingID].PeerID = "12D3KooWRGyuZjTiZ2sWmrcdqgCzbf5eaWZC71Wi419g7UvFsSxD"

	_, err := f.verifyDoc(f.doc())
	assertDenied(t, err, ReasonCallerPeerMismatch)
}

// ------------------------------------------------------------------- V7 ---

func TestVerify_V7_RejectsExpiredAttestation(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	env := f.sign(doc)

	f.now = f.now.Add(60 * time.Second) // past expiry + skew
	_, err := f.verify(env)
	assertDenied(t, err, ReasonExpired)
}

func TestVerify_V7_RejectsFutureAttestation(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.IssuedAt = f.now.Add(10 * time.Minute).Format(time.RFC3339)
	doc.ExpiresAt = f.now.Add(10*time.Minute + 30*time.Second).Format(time.RFC3339)

	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonNotYetValid)
}

// TestVerify_V7_RejectsOverlongTTL stops a caller self-issuing a long-lived
// credential, which would defeat the point of per-call attestation and outlive
// nonce retention.
func TestVerify_V7_RejectsOverlongTTL(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.ExpiresAt = f.now.Add(365 * 24 * time.Hour).Format(time.RFC3339)

	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonTTLTooLong)
}

func TestVerify_V7_ToleratesClockSkew(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	env := f.sign(doc)

	// Responder clock is 3s behind the issuer; within the 5s tolerance.
	f.now = f.now.Add(-3 * time.Second)
	if _, err := f.verify(env); err != nil {
		t.Fatalf("attestation within clock skew was rejected: %v", err)
	}
}

// TestVerify_V7_RejectsNonUTCTimestamp pins that the canonical form is
// unambiguous: "+00:00" denotes the same instant as "Z" but is a different byte
// sequence, and the document is signed as bytes.
//
// Signed without validation because a conforming client would never emit this;
// the point is that the VERIFIER refuses it regardless.
func TestVerify_V7_RejectsNonUTCTimestamp(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.IssuedAt = "2026-08-23T12:00:00+00:00"

	_, err := f.verify(f.signUnchecked(doc))
	assertDenied(t, err, ReasonMalformed)
}

func TestVerify_V7_RejectsExpiryBeforeIssue(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.ExpiresAt = f.now.Add(-time.Second).Format(time.RFC3339)

	_, err := f.verifyDoc(doc)
	assertDenied(t, err, ReasonBadTimestamp)
}

// ------------------------------------------------------------------- V8 ---

func TestVerify_V8_RejectsReplay(t *testing.T) {
	f := newFixture(t)
	env := f.sign(f.doc())

	if _, err := f.verify(env); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := f.verify(env)
	assertDenied(t, err, ReasonNonceReused)
}

// TestVerify_V8_ConcurrentReplayAdmitsExactlyOne is the check that proves the
// nonce mechanism is real rather than decorative.
func TestVerify_V8_ConcurrentReplayAdmitsExactlyOne(t *testing.T) {
	f := newFixture(t)
	env := f.sign(f.doc())

	const racers = 32
	var wg sync.WaitGroup
	results := make([]error, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, results[i] = f.verifier.Verify(context.Background(), env, f.req)
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, reused int
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case ReasonOf(err) == ReasonNonceReused:
			reused++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d concurrent replays succeeded, want exactly 1; "+
			"nonce consumption is not atomic", ok, racers)
	}
	if reused != racers-1 {
		t.Fatalf("got %d nonce_reused denials, want %d", reused, racers-1)
	}
}

// TestVerify_V8_NonceIsScopedToBinding confirms two different callers may pick
// the same random nonce without either being denied.
func TestVerify_V8_NonceIsScopedToBinding(t *testing.T) {
	f := newFixture(t)

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	const otherBindingID = "bnd_eeeeeeeeeeeeeeeeeeeeeeee"
	const otherCAID = "eip155:31337:0x1111111111111111111111111111111111111111/8"
	const otherPeer = "12D3KooWRGyuZjTiZ2sWmrcdqgCzbf5eaWZC71Wi419g7UvFsSxD"
	f.trust.bindings[otherBindingID] = &CallerBinding{
		BindingID: otherBindingID, CAID: otherCAID, PeerID: otherPeer,
		SidecarKey: otherPub, Active: true,
	}

	shared := newTestNonce(t)

	first := f.doc()
	first.Nonce = shared
	if _, err := f.verifyDoc(first); err != nil {
		t.Fatalf("first caller: %v", err)
	}

	second := f.doc()
	second.Nonce = shared
	second.CallerCAID = otherCAID
	second.CallerPeerID = otherPeer
	second.CallerBindingID = otherBindingID
	env, err := Sign(second, otherPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := f.verify(env); err != nil {
		t.Fatalf("a different caller reusing the same random nonce was denied: %v", err)
	}
}

// TestVerify_V8_NonceNotBurnedByFailedChecks is the attestation-layer analogue
// of TH-17: a caller who cannot pass verification must not be able to consume
// nonces belonging to a binding it does not control.
func TestVerify_V8_NonceNotBurnedByFailedChecks(t *testing.T) {
	f := newFixture(t)

	doc := f.doc()
	nonce := doc.Nonce

	// Fail at V5 with a forged signature.
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	forged, err := Sign(doc, attackerPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := f.verify(forged); err == nil {
		t.Fatal("forged attestation was accepted")
	}

	if f.store.Len() != 0 {
		t.Fatal("a failed verification consumed a nonce; an attacker could burn arbitrary nonces")
	}

	// The legitimate holder can still use that nonce.
	good := f.doc()
	good.Nonce = nonce
	if _, err := f.verifyDoc(good); err != nil {
		t.Fatalf("legitimate use after a forged attempt was denied: %v", err)
	}
}

// ------------------------------------------------------- structure/format --

func TestValidate_RejectsMalformedDocuments(t *testing.T) {
	f := newFixture(t)

	mutations := map[string]func(*Document){
		"wrong type":            func(d *Document) { d.Type = "urn:satm:something-else" },
		"empty mesh":            func(d *Document) { d.MeshID = "" },
		"empty control plane":   func(d *Document) { d.ControlPlane = "" },
		"checksummed caid":      func(d *Document) { d.CallerCAID = strings.ToUpper(d.CallerCAID) },
		"caid without agent id": func(d *Document) { d.CallerCAID = "eip155:31337:0x1111111111111111111111111111111111111111" },
		"empty service":         func(d *Document) { d.Service = "" },
		"empty tool":            func(d *Document) { d.Tool = "" },
		"uppercase argsHash":    func(d *Document) { d.ArgsHash = "0x" + strings.ToUpper(strings.Repeat("a", 64)) },
		"short argsHash":        func(d *Document) { d.ArgsHash = "0xdeadbeef" },
		"argsHash no prefix":    func(d *Document) { d.ArgsHash = strings.Repeat("a", 64) },
		"short nonce":           func(d *Document) { d.Nonce = "abc" },
		"nonce not base64url":   func(d *Document) { d.Nonce = strings.Repeat("+", 24) },
		"malformed bindingId":   func(d *Document) { d.CallerBindingID = "not-a-binding-id" },
		"bad peer id":           func(d *Document) { d.CallerPeerID = "0OIl-invalid-base58" },
	}

	for name, mutate := range mutations {
		doc := f.doc()
		mutate(doc)
		if err := doc.Validate(); err == nil {
			t.Errorf("%s: malformed document passed Validate", name)
		}
		// Correctly signed, so structure is the ONLY thing wrong. Without this
		// the test would pass even if Verify happened to deny for an unrelated
		// reason such as a missing signature.
		_, err := f.verify(f.signUnchecked(doc))
		if err == nil {
			t.Errorf("%s: malformed document passed Verify", name)
			continue
		}
		if got := ReasonOf(err); got != ReasonMalformed {
			t.Errorf("%s: reason = %q, want %q", name, got, ReasonMalformed)
		}
	}
}

func TestSign_RefusesInvalidDocument(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()
	doc.Tool = ""
	if _, err := Sign(doc, f.callerPriv); err == nil {
		t.Fatal("an invalid document was signed; the error would surface much later as a denial")
	}
}

func TestSign_RejectsWrongKeySize(t *testing.T) {
	f := newFixture(t)
	if _, err := Sign(f.doc(), ed25519.PrivateKey([]byte{1, 2, 3})); err == nil {
		t.Fatal("a malformed key was accepted")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	f := newFixture(t)
	env := f.sign(f.doc())

	encoded, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseEnvelope(encoded)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if _, err := f.verify(parsed); err != nil {
		t.Fatalf("round-tripped envelope failed verification: %v", err)
	}
}

func TestParseEnvelope_RejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"not base64url": "!!!!",
		"not json":      base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"no document":   base64.RawURLEncoding.EncodeToString([]byte(`{"signature":"aaaa"}`)),
		"oversized":     strings.Repeat("A", maxEnvelopeBytes+1),
	}
	for name, s := range cases {
		if _, err := ParseEnvelope(s); err == nil {
			t.Errorf("%s: was accepted", name)
		}
	}
}

func TestCanonicalizationIsStable(t *testing.T) {
	f := newFixture(t)
	doc := f.doc()

	first, err := doc.Canonicalize()
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := doc.Canonicalize()
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}
		if string(got) != string(first) {
			t.Fatalf("canonicalization is not deterministic:\n %s\n %s", first, got)
		}
	}

	// Keys must be sorted, so "argsHash" precedes "callerCaid" precedes "type".
	s := string(first)
	if !strings.HasPrefix(s, `{"argsHash":`) {
		t.Fatalf("canonical form does not start with the lowest-sorting key: %s", s[:40])
	}
}

// ---------------------------------------------------------- nonce store ---

func TestMemoryNonceStorePurge(t *testing.T) {
	s := NewMemoryNonceStore()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	ctx := context.Background()
	if err := s.Consume(ctx, callerBindingID, "expired-soon", now.Add(10*time.Second)); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := s.Consume(ctx, callerBindingID, "long-lived", now.Add(time.Hour)); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}

	now = now.Add(time.Minute)
	if removed := s.Purge(); removed != 1 {
		t.Fatalf("Purge removed %d, want 1", removed)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d after purge, want 1", s.Len())
	}
}

func TestDescribeChecksCoversV1toV8(t *testing.T) {
	checks := DescribeChecks()
	if len(checks) != 8 {
		t.Fatalf("DescribeChecks returned %d entries, want 8", len(checks))
	}
	for i, c := range checks {
		want := "V" + string(rune('1'+i))
		if !strings.HasPrefix(c, want) {
			t.Errorf("entry %d = %q, want it to start with %q", i, c, want)
		}
	}
}
