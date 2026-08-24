// Package attest implements the SATM Call Attestation (SPECIFICATION.md 6.3.3).
//
// # Why this exists
//
// This is not defence in depth. It is the ONLY mechanism by which an inbound
// sidecar learns who called it.
//
// Spike S-5 established the constraint empirically: SAM authenticates the peer
// at the transport layer via Biscuit, but does not pass the authenticated caller
// identity to a locally-spawned service. `internal/node/gate.go` describes the
// path as a "dumb-pipe proxy" and calls `mcpSvc.HandleStreamPassThrough(s)`,
// forwarding the raw stream; the request context carries the caller's PeerID but
// uses it only to select the target service and then discards it. The spawned
// subprocess sees no SAM_*, PEER_* or CALLER_* environment variables.
//
// So if the sidecar simply trusted a `peerId` field in the request body, any
// caller could name someone else's CAID and inherit their trust tier and
// spending authority. That is threat TH-7a.
//
// # The mechanism
//
// Each agent's sidecar holds an Ed25519 sidecar key whose public half sits
// inside the binding document, and is therefore covered by BOTH binding
// signatures. Authority for the hot per-call key is inherited from the two cold
// proofs rather than asserted separately.
//
// The initiator signs one attestation per call. The responder verifies all of
// V1..V8 and denies on the first failure.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/internal/canonicaljson"
)

// DocumentType is the schema identifier carried in every attestation.
const DocumentType = "urn:satm:call-attestation-v1"

// Document is the signed attestation payload.
//
// Field encodings are normative. Both the signer and the verifier canonicalise
// with RFC 8785 and hash with SHA-256, so any disagreement about encoding shows
// up as a signature failure rather than as a security hole.
type Document struct {
	Type         string `json:"type"`
	MeshID       string `json:"meshId"`
	ControlPlane string `json:"controlPlane"`

	// Caller identity. CallerBindingID is load-bearing for revocation: because
	// it is inside the signature and must be the caller's CURRENT binding,
	// re-binding an agent invalidates every outstanding attestation signed under
	// the old sidecar key. The binding id doubles as a key epoch.
	CallerCAID      string `json:"callerCaid"`
	CallerPeerID    string `json:"callerPeerId"`
	CallerBindingID string `json:"callerBindingId"`

	// Target identity, checked against the responder's own current values (V2).
	TargetCAID      string `json:"targetCaid"`
	TargetPeerID    string `json:"targetPeerId"`
	TargetBindingID string `json:"targetBindingId"`

	// Service and Tool scope the attestation to one specific operation (V3).
	Service string `json:"service"`
	Tool    string `json:"tool"`

	// ArgsHash is "0x" + lowercase hex of SHA-256 over the canonical JSON of the
	// call arguments (V4).
	ArgsHash string `json:"argsHash"`

	// Nonce is base64url (unpadded) of at least 16 random bytes.
	Nonce string `json:"nonce"`

	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
}

var (
	// argsHashPattern requires lowercase hex. Mixed case would let the same
	// logical hash have two encodings, and the attestation is compared by exact
	// string equality.
	argsHashPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	// noncePattern matches unpadded base64url of >= 16 bytes (22+ chars).
	noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,}$`)
	// caidPattern is {namespace}:{chainId}:0x{40 lowercase hex}/{decimal}.
	caidPattern = regexp.MustCompile(`^[a-z0-9]{3,8}:[0-9]{1,32}:0x[0-9a-f]{40}/(0|[1-9][0-9]*)$`)
	// peerIDPattern is a coarse base58btc shape check.
	peerIDPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{44,64}$`)
	// bindingIDPattern matches the broker's record id format.
	bindingIDPattern = regexp.MustCompile(`^bnd_[0-9a-f]{24}$`)
)

// Validate performs structural checks only. It says nothing about authenticity;
// that is Verify's job.
func (d *Document) Validate() error {
	if d.Type != DocumentType {
		return fmt.Errorf("type must be %q, got %q", DocumentType, d.Type)
	}
	if d.MeshID == "" {
		return fmt.Errorf("meshId must not be empty")
	}
	if d.ControlPlane == "" {
		return fmt.Errorf("controlPlane must not be empty")
	}
	if !caidPattern.MatchString(d.CallerCAID) {
		return fmt.Errorf("callerCaid %q is not a canonical lowercase CAID", d.CallerCAID)
	}
	if !caidPattern.MatchString(d.TargetCAID) {
		return fmt.Errorf("targetCaid %q is not a canonical lowercase CAID", d.TargetCAID)
	}
	if !peerIDPattern.MatchString(d.CallerPeerID) {
		return fmt.Errorf("callerPeerId %q is not a plausible base58btc peer id", d.CallerPeerID)
	}
	if !peerIDPattern.MatchString(d.TargetPeerID) {
		return fmt.Errorf("targetPeerId %q is not a plausible base58btc peer id", d.TargetPeerID)
	}
	if !bindingIDPattern.MatchString(d.CallerBindingID) {
		return fmt.Errorf("callerBindingId %q is malformed", d.CallerBindingID)
	}
	if !bindingIDPattern.MatchString(d.TargetBindingID) {
		return fmt.Errorf("targetBindingId %q is malformed", d.TargetBindingID)
	}
	if d.Service == "" {
		return fmt.Errorf("service must not be empty")
	}
	if d.Tool == "" {
		return fmt.Errorf("tool must not be empty")
	}
	if !argsHashPattern.MatchString(d.ArgsHash) {
		return fmt.Errorf("argsHash %q must be 0x + 64 lowercase hex chars", d.ArgsHash)
	}
	if !noncePattern.MatchString(d.Nonce) {
		return fmt.Errorf("nonce %q must be unpadded base64url of at least 16 bytes", d.Nonce)
	}
	if _, err := parseRFC3339UTC("issuedAt", d.IssuedAt); err != nil {
		return err
	}
	if _, err := parseRFC3339UTC("expiresAt", d.ExpiresAt); err != nil {
		return err
	}
	return nil
}

// parseRFC3339UTC requires a literal trailing "Z".
//
// Accepting "+00:00" would mean two byte sequences denote the same instant, and
// the document is signed as bytes -- so the canonical form must be unambiguous.
func parseRFC3339UTC(field, v string) (time.Time, error) {
	if !strings.HasSuffix(v, "Z") {
		return time.Time{}, fmt.Errorf("%s %q must be RFC 3339 UTC ending in Z", field, v)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q is not a valid RFC 3339 timestamp: %w", field, v, err)
	}
	return t.UTC(), nil
}

// IssuedAtTime parses IssuedAt.
func (d *Document) IssuedAtTime() (time.Time, error) {
	return parseRFC3339UTC("issuedAt", d.IssuedAt)
}

// ExpiresAtTime parses ExpiresAt.
func (d *Document) ExpiresAtTime() (time.Time, error) {
	return parseRFC3339UTC("expiresAt", d.ExpiresAt)
}

// Canonicalize returns the RFC 8785 canonical form.
//
// The round-trip through a generic map is deliberate: key ordering must come
// from JCS rules, not from Go struct field order, which is not a stable contract
// and would silently change if someone reordered the struct.
func (d *Document) Canonicalize() ([]byte, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation: %w", err)
	}
	var generic map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("normalize attestation: %w", err)
	}
	return canonicaljson.Encode(generic)
}

// SigningDigest returns SHA-256 over the canonical JSON.
func (d *Document) SigningDigest() ([32]byte, error) {
	canonical, err := d.Canonicalize()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// Envelope is the wire form: the document plus its signature.
//
// It is transported as a base64url-encoded MCP argument named satm_attestation.
type Envelope struct {
	Document  *Document `json:"document"`
	Signature string    `json:"signature"` // base64url, unpadded
}

// Sign produces an envelope signed with the sidecar key.
func Sign(doc *Document, key ed25519.PrivateKey) (*Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sidecar key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("refusing to sign an invalid attestation: %w", err)
	}
	digest, err := doc.SigningDigest()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, digest[:])
	return &Envelope{
		Document:  doc,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// Marshal encodes an envelope for transport as an MCP argument.
func (e *Envelope) Marshal() (string, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// maxEnvelopeBytes bounds a decoded envelope. Attestations are well under 2 KiB;
// the cap exists so an unauthenticated caller cannot force large allocations
// before any signature has been checked.
const maxEnvelopeBytes = 16 * 1024

// ParseEnvelope decodes a transported attestation.
func ParseEnvelope(encoded string) (*Envelope, error) {
	if len(encoded) > maxEnvelopeBytes {
		return nil, fmt.Errorf("attestation envelope exceeds %d bytes", maxEnvelopeBytes)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("attestation is not valid unpadded base64url: %w", err)
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("attestation envelope is not valid JSON: %w", err)
	}
	if e.Document == nil {
		return nil, fmt.Errorf("attestation envelope has no document")
	}
	return &e, nil
}

// HashArgs computes the V4 argument hash.
//
// Arguments are canonicalised with the same RFC 8785 encoder used for the
// document itself, so caller and callee agree byte-for-byte regardless of map
// iteration order or which language produced the call.
func HashArgs(args map[string]any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	// Normalise through a JSON round-trip so numbers become json.Number and the
	// canonical encoder sees exactly the types it supports. Passing a raw Go map
	// containing float64 would otherwise be rejected at encode time.
	raw, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("marshal args: %w", err)
	}
	var generic any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return "", fmt.Errorf("normalize args: %w", err)
	}
	canonical, err := canonicaljson.Encode(generic)
	if err != nil {
		return "", fmt.Errorf("canonicalize args: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "0x" + hexLower(sum[:]), nil
}

const hexDigits = "0123456789abcdef"

// hexLower renders bytes as lowercase hex. Written out rather than using
// encoding/hex so the lowercase guarantee is visible at the point of use: the
// value is compared by exact string equality, and SAM label matching elsewhere
// in SATM is case-sensitive (TH-18).
func hexLower(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
