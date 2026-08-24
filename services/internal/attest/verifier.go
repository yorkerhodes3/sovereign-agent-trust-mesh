package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CallerBinding is the responder's view of a caller's binding, as published by
// the broker's Trust API.
type CallerBinding struct {
	BindingID string
	CAID      string
	PeerID    string
	// SidecarKey is the raw 32-byte Ed25519 public key.
	SidecarKey []byte
	// Active reports whether this is the CURRENT binding for the CAID. A
	// superseded or revoked binding is still resolvable -- so that a denial can
	// say WHY rather than "unknown" -- but must not authorise a call.
	Active bool
}

// TrustAPI resolves caller bindings. Implemented against the broker.
type TrustAPI interface {
	// BindingByID resolves a binding id. Returns ErrBindingNotFound if the
	// broker has no record of it.
	BindingByID(ctx context.Context, bindingID string) (*CallerBinding, error)
}

// ErrBindingNotFound is returned by TrustAPI when a binding id is unknown.
var ErrBindingNotFound = errors.New("binding not found")

// NonceStore consumes attestation nonces (V8).
//
// Consume MUST be atomic and MUST happen BEFORE the request is forwarded to the
// served tool. Checking first and consuming afterwards would leave a window in
// which two concurrent replays both pass; consuming after forwarding would mean
// a crash mid-call releases the nonce.
type NonceStore interface {
	// Consume atomically records (bindingID, nonce). It returns ErrNonceReused
	// if the pair was already consumed.
	Consume(ctx context.Context, bindingID, nonce string, expiresAt time.Time) error
}

// ErrNonceReused is returned by NonceStore.Consume on a duplicate.
var ErrNonceReused = errors.New("attestation nonce already consumed")

// Self is the responder's own current identity, from its own binding.
//
// This comes from the sidecar's configuration and its own binding record -- NOT
// from the request body. A body-supplied `self` is exactly threat TH-7a: it
// would let a caller nominate which identity it is talking to and thereby
// satisfy V2 against a target of its own choosing.
type Self struct {
	CAID      string
	PeerID    string
	BindingID string
}

// Config parameterises verification.
type Config struct {
	MeshID       string
	ControlPlane string
	Self         Self

	// TTL bounds expiresAt - issuedAt (V7). Without an upper bound a caller
	// could self-issue an attestation valid for a year, defeating the point of
	// per-call authentication and outliving nonce retention.
	TTL time.Duration

	// ClockSkew tolerated on issuedAt.
	ClockSkew time.Duration

	// Now is injectable for deterministic tests.
	Now func() time.Time
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// Verifier runs checks V1..V8.
type Verifier struct {
	cfg   Config
	trust TrustAPI
	store NonceStore
}

// NewVerifier constructs a Verifier, rejecting configurations that would be
// silently insecure.
func NewVerifier(cfg Config, trust TrustAPI, store NonceStore) (*Verifier, error) {
	if cfg.MeshID == "" {
		return nil, fmt.Errorf("attest config: meshId is required")
	}
	if cfg.ControlPlane == "" {
		return nil, fmt.Errorf("attest config: controlPlane is required")
	}
	if cfg.Self.CAID == "" || cfg.Self.PeerID == "" || cfg.Self.BindingID == "" {
		// Without a complete self-identity V2 cannot be evaluated, and an
		// unevaluated V2 means a captured attestation replays at any callee.
		return nil, fmt.Errorf("attest config: self caid, peerId and bindingId are all required; " +
			"without them check V2 cannot be enforced and any captured attestation replays here")
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("attest config: ttl must be positive (check V7)")
	}
	if trust == nil {
		return nil, fmt.Errorf("attest config: a TrustAPI is required")
	}
	if store == nil {
		return nil, fmt.Errorf("attest config: a NonceStore is required (check V8)")
	}
	return &Verifier{cfg: cfg, trust: trust, store: store}, nil
}

// Request is the actual call being served, as observed by the responder.
//
// These values come from the received MCP request, NOT from the attestation.
// Comparing the attestation against itself would be vacuous.
type Request struct {
	Service string
	Tool    string
	Args    map[string]any
}

// Result is a successful verification.
type Result struct {
	Caller *CallerBinding
	Doc    *Document
}

// Verify runs checks V1 through V8 IN ORDER and denies on the first failure.
//
// The ordering is deliberate. Cheap local checks come before any network call so
// an attacker cannot use malformed attestations to generate load on the broker.
// V8 is LAST because consuming a nonce is a side effect: doing it earlier would
// let an unauthenticated caller burn nonces belonging to a binding it does not
// control, which is the attestation-layer analogue of threat TH-17.
func (v *Verifier) Verify(ctx context.Context, env *Envelope, req Request) (*Result, error) {
	if env == nil || env.Document == nil {
		return nil, denied(ReasonMalformed, "parse", "no attestation document")
	}
	doc := env.Document
	if err := doc.Validate(); err != nil {
		return nil, denied(ReasonMalformed, "parse", err.Error())
	}

	if err := v.checkMesh(doc); err != nil { // V1
		return nil, err
	}
	if err := v.checkTarget(doc); err != nil { // V2
		return nil, err
	}
	if err := v.checkOperation(doc, req); err != nil { // V3
		return nil, err
	}
	if err := v.checkArgs(doc, req); err != nil { // V4
		return nil, err
	}
	if err := v.checkFreshness(doc); err != nil { // V7 (before the network call)
		return nil, err
	}

	caller, err := v.resolveCaller(ctx, doc) // V5 lookup
	if err != nil {
		return nil, err
	}
	if err := verifySignature(doc, env.Signature, caller.SidecarKey); err != nil { // V5
		return nil, err
	}
	if err := checkCallerCurrency(doc, caller); err != nil { // V6
		return nil, err
	}
	if err := v.consumeNonce(ctx, doc); err != nil { // V8
		return nil, err
	}

	return &Result{Caller: caller, Doc: doc}, nil
}

// checkMesh is V1: the attestation must name THIS mesh.
func (v *Verifier) checkMesh(doc *Document) error {
	if doc.MeshID != v.cfg.MeshID {
		return denied(ReasonWrongMesh, "V1",
			fmt.Sprintf("attestation names mesh %q, this mesh is %q", doc.MeshID, v.cfg.MeshID))
	}
	if doc.ControlPlane != v.cfg.ControlPlane {
		return denied(ReasonWrongControlPlane, "V1",
			"attestation names a different control plane")
	}
	return nil
}

// checkTarget is V2: the attestation must be addressed to THIS agent, at its
// CURRENT binding.
//
// Including bindingId, not just CAID and PeerID, is what makes a captured
// attestation stop working after the responder re-binds.
func (v *Verifier) checkTarget(doc *Document) error {
	if doc.TargetCAID != v.cfg.Self.CAID {
		return denied(ReasonWrongTarget, "V2",
			"attestation is addressed to a different agent")
	}
	if doc.TargetPeerID != v.cfg.Self.PeerID {
		return denied(ReasonWrongTarget, "V2",
			"attestation is addressed to a different peer")
	}
	if doc.TargetBindingID != v.cfg.Self.BindingID {
		return denied(ReasonWrongTarget, "V2",
			"attestation was issued against a superseded binding of this agent")
	}
	return nil
}

// checkOperation is V3: the attestation must cover the operation actually being
// served.
//
// Not optional. Without it a caller obtains a cheap attestation for a read-only
// tool and presents it to an asset-moving one -- the attestation is genuine, the
// signature verifies, and the privilege escalation is total.
func (v *Verifier) checkOperation(doc *Document, req Request) error {
	if doc.Service != req.Service {
		return denied(ReasonWrongService, "V3",
			fmt.Sprintf("attestation covers service %q, request is for %q", doc.Service, req.Service))
	}
	if doc.Tool != req.Tool {
		return denied(ReasonWrongTool, "V3",
			fmt.Sprintf("attestation covers tool %q, request is for %q", doc.Tool, req.Tool))
	}
	return nil
}

// checkArgs is V4: the attestation must cover the arguments actually received.
func (v *Verifier) checkArgs(doc *Document, req Request) error {
	got, err := HashArgs(req.Args)
	if err != nil {
		return denied(ReasonMalformed, "V4", "could not canonicalize request arguments: "+err.Error())
	}
	// Constant-time comparison. The window is small but the cost is zero, and
	// argsHash is attacker-influenced.
	if subtle.ConstantTimeCompare([]byte(got), []byte(doc.ArgsHash)) != 1 {
		return denied(ReasonArgsMismatch, "V4",
			"request arguments do not match the attested argsHash")
	}
	return nil
}

// checkFreshness is V7.
func (v *Verifier) checkFreshness(doc *Document) error {
	issued, err := doc.IssuedAtTime()
	if err != nil {
		return denied(ReasonBadTimestamp, "V7", err.Error())
	}
	expires, err := doc.ExpiresAtTime()
	if err != nil {
		return denied(ReasonBadTimestamp, "V7", err.Error())
	}
	if !expires.After(issued) {
		return denied(ReasonBadTimestamp, "V7", "expiresAt must be after issuedAt")
	}
	if expires.Sub(issued) > v.cfg.TTL {
		return denied(ReasonTTLTooLong, "V7",
			fmt.Sprintf("attestation lifetime %s exceeds the %s maximum", expires.Sub(issued), v.cfg.TTL))
	}

	now := v.cfg.now()
	if now.Before(issued.Add(-v.cfg.ClockSkew)) {
		return denied(ReasonNotYetValid, "V7", "attestation is not yet valid")
	}
	if now.After(expires.Add(v.cfg.ClockSkew)) {
		return denied(ReasonExpired, "V7", "attestation has expired")
	}
	return nil
}

// resolveCaller fetches the caller's binding for V5/V6.
func (v *Verifier) resolveCaller(ctx context.Context, doc *Document) (*CallerBinding, error) {
	caller, err := v.trust.BindingByID(ctx, doc.CallerBindingID)
	if err != nil {
		if errors.Is(err, ErrBindingNotFound) {
			return nil, denied(ReasonUnknownCallerBinding, "V5",
				"the broker has no record of the caller's binding")
		}
		// An unreachable Trust API is an infrastructure failure, not a verdict.
		// Reporting it as a denial would misattribute the fault and, worse,
		// train operators to ignore denials during an outage.
		return nil, &Error{
			Reason: ReasonTrustAPIUnavailable,
			Check:  "V5",
			Detail: "could not resolve the caller's binding",
			Err:    err,
		}
	}
	if caller == nil {
		return nil, denied(ReasonUnknownCallerBinding, "V5",
			"the broker has no record of the caller's binding")
	}
	return caller, nil
}

// verifySignature is V5.
func verifySignature(doc *Document, signature string, sidecarKey []byte) error {
	if len(sidecarKey) != ed25519.PublicKeySize {
		return denied(ReasonBadSignature, "V5",
			fmt.Sprintf("caller sidecar key is %d bytes, expected %d", len(sidecarKey), ed25519.PublicKeySize))
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return denied(ReasonBadSignature, "V5", "signature is not valid unpadded base64url")
	}
	if len(sig) != ed25519.SignatureSize {
		return denied(ReasonBadSignature, "V5",
			fmt.Sprintf("signature is %d bytes, expected %d", len(sig), ed25519.SignatureSize))
	}
	digest, err := doc.SigningDigest()
	if err != nil {
		return denied(ReasonMalformed, "V5", err.Error())
	}
	if !ed25519.Verify(ed25519.PublicKey(sidecarKey), digest[:], sig) {
		return denied(ReasonBadSignature, "V5",
			"signature does not verify against the caller's attested sidecar key")
	}
	return nil
}

// checkCallerCurrency is V6.
//
// This is what makes the sidecar key revocable. Because callerBindingId is
// inside the signature and must be the caller's CURRENT binding, re-binding an
// agent -- which the broker does atomically at check B15 -- invalidates every
// outstanding attestation signed under the old sidecar key.
func checkCallerCurrency(doc *Document, caller *CallerBinding) error {
	if !caller.Active {
		return denied(ReasonBindingSuperseded, "V6",
			"the caller's binding is no longer active; it was revoked or superseded by a re-bind")
	}
	if caller.CAID != doc.CallerCAID {
		// The signature verified, so the caller holds the sidecar key for this
		// binding -- but the binding belongs to a different agent than claimed.
		return denied(ReasonCallerPeerMismatch, "V6",
			"the attested callerCaid does not match the binding it names")
	}
	if caller.PeerID != doc.CallerPeerID {
		return denied(ReasonCallerPeerMismatch, "V6",
			"the attested callerPeerId does not match the binding it names")
	}
	return nil
}

// consumeNonce is V8.
func (v *Verifier) consumeNonce(ctx context.Context, doc *Document) error {
	expires, err := doc.ExpiresAtTime()
	if err != nil {
		return denied(ReasonBadTimestamp, "V8", err.Error())
	}
	if err := v.store.Consume(ctx, doc.CallerBindingID, doc.Nonce, expires); err != nil {
		if errors.Is(err, ErrNonceReused) {
			return denied(ReasonNonceReused, "V8", "this attestation has already been used")
		}
		return &Error{
			Reason: ReasonTrustAPIUnavailable,
			Check:  "V8",
			Detail: "could not consume the attestation nonce",
			Err:    err,
		}
	}
	return nil
}

// DescribeChecks returns the ordered check list, for documentation and tests.
func DescribeChecks() []string {
	return []string{
		"V1 mesh and control plane",
		"V2 target is this agent at its current binding",
		"V3 service and tool match the served request",
		"V4 argsHash matches the received arguments",
		"V5 signature verifies against the caller's sidecar key",
		"V6 caller binding is current and matches the claimed identity",
		"V7 freshness within TTL and clock skew",
		"V8 nonce consumed atomically",
	}
}

// SelfFromBinding is a small helper so callers construct Self from a binding
// record rather than assembling it field by field at each call site.
func SelfFromBinding(caid, peerID, bindingID string) Self {
	return Self{
		CAID:      strings.TrimSpace(caid),
		PeerID:    strings.TrimSpace(peerID),
		BindingID: strings.TrimSpace(bindingID),
	}
}
