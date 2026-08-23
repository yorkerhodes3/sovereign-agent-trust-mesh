// Package binding implements the Agent Mesh Binding (AMB): the dual-signature
// proof that ties a libp2p PeerID to an ERC-8004 agent identity.
//
// This is the core novel mechanism of SATM. Everything else in the system
// composes existing standards; this is the joint that does not exist anywhere
// upstream. See SPECIFICATION.md section 4.
//
// The short version of why it takes two signatures:
//
//   - A chain-side claim alone proves nothing about the node. Anyone can publish
//     a registration file naming any PeerID.
//   - A node-side claim alone proves nothing about the agent. Any node can
//     assert it is agentId 42.
//
// So a binding is ONE canonical document signed TWICE: once by the libp2p host
// key (proving control of the PeerID) and once by the ERC-8004 agentWallet via
// EIP-712 (proving control of the on-chain identity). Forging one requires both
// private keys.
package binding

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// DocumentType is the schema identifier carried in every binding document.
const DocumentType = "urn:satm:binding-v1"

// Document is the canonical binding payload. Both signatures cover it.
//
// Field encodings are NORMATIVE (SPECIFICATION.md 4.3). They are spelled out
// because this struct is hashed and cross-signed by two different signature
// systems, and an under-specified encoding is a substitution vulnerability, not
// a cosmetic issue: if a verifier and a signer disagree about how to render a
// field, an attacker gets to choose the difference.
type Document struct {
	// Type MUST be DocumentType.
	Type string `json:"type"`

	// AgentRegistry is a CAIP-style {namespace}:{chainId}:{address} tuple.
	// The address MUST be lowercase hex with an 0x prefix -- NOT EIP-55
	// checksummed -- so canonicalisation is unambiguous and so the value can be
	// compared byte-for-byte against SAM labels, whose matching is exact and
	// case-sensitive.
	AgentRegistry string `json:"agentRegistry"`

	// AgentID is a DECIMAL STRING, not a number. ERC-721 token ids are uint256
	// and JSON numbers are float64 in most parsers, which silently loses
	// precision above 2^53.
	AgentID string `json:"agentId"`

	// AgentWallet is lowercase 0x hex, 20 bytes.
	AgentWallet string `json:"agentWallet"`

	// PeerID is a libp2p PeerID in canonical base58btc text form.
	PeerID string `json:"peerId"`

	// SidecarKey is "ed25519:" + base58btc of the raw 32-byte public key. It
	// rides inside the binding so a hot per-call signing key inherits its
	// authority from both cold proofs (SPECIFICATION.md 6.3.3).
	SidecarKey string `json:"sidecarKey"`

	// MeshID and ControlPlane bind the document to ONE mesh. Without them a
	// fully valid binding could be replayed against a different deployment
	// (threat TH-3).
	MeshID       string `json:"meshId"`
	ControlPlane string `json:"controlPlane"`

	// Nonce is a DECIMAL STRING of a 256-bit CSPRNG value, so it maps to an
	// EIP-712 uint256 with no conversion ambiguity.
	Nonce string `json:"nonce"`

	// IssuedAt and ExpiresAt are RFC 3339 UTC, second precision, "Z" suffix.
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
}

var (
	// caipPattern matches {namespace}:{chainId}:{0x-address}, lowercase hex only.
	caipPattern = regexp.MustCompile(`^[a-z0-9]{3,8}:[0-9]{1,32}:0x[0-9a-f]{40}$`)
	// addrPattern matches a lowercase 0x-prefixed 20-byte address.
	addrPattern = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	// decimalPattern matches an unsigned decimal integer with no leading zeros
	// (except "0" itself). Leading zeros would let two distinct byte sequences
	// carry the same numeric value.
	decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	// sidecarKeyPattern matches "ed25519:" + base58btc payload.
	sidecarKeyPattern = regexp.MustCompile(`^ed25519:[1-9A-HJ-NP-Za-km-z]{40,64}$`)
	// peerIDPattern is a coarse base58btc shape check. Real validation is
	// cryptographic (check B4) -- this only rejects obvious junk early.
	peerIDPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{44,64}$`)
	// meshIDPattern mirrors SAM's label-value constraints.
	meshIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)
)

// maxUint256 is 2^256 - 1, the upper bound for Nonce and AgentID.
var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// Validate checks structural well-formedness only. It performs NO cryptography
// and NO chain access; those are checks B4-B13 in the verifier.
//
// Returning on the first problem is deliberate: callers surface these as reason
// codes, and "the first thing wrong with this document" is more actionable to an
// operator than an aggregated list.
func (d *Document) Validate() error {
	if d.Type != DocumentType {
		return fmt.Errorf("type must be %q, got %q", DocumentType, d.Type)
	}
	if !caipPattern.MatchString(d.AgentRegistry) {
		return fmt.Errorf("agentRegistry %q is not a lowercase CAIP tuple "+
			"{namespace}:{chainId}:0x{40 hex}", d.AgentRegistry)
	}
	if !decimalPattern.MatchString(d.AgentID) {
		return fmt.Errorf("agentId %q must be a decimal string with no leading zeros", d.AgentID)
	}
	if n, ok := new(big.Int).SetString(d.AgentID, 10); !ok || n.Cmp(maxUint256) > 0 {
		return fmt.Errorf("agentId %q does not fit in uint256", d.AgentID)
	}
	if !addrPattern.MatchString(d.AgentWallet) {
		return fmt.Errorf("agentWallet %q must be lowercase 0x-prefixed 20-byte hex", d.AgentWallet)
	}
	if !peerIDPattern.MatchString(d.PeerID) {
		return fmt.Errorf("peerId %q is not a plausible base58btc peer id", d.PeerID)
	}
	if !sidecarKeyPattern.MatchString(d.SidecarKey) {
		return fmt.Errorf("sidecarKey %q must be ed25519:<base58btc>", d.SidecarKey)
	}
	if !meshIDPattern.MatchString(d.MeshID) {
		return fmt.Errorf("meshId %q must be 1-63 chars of [A-Za-z0-9._-]", d.MeshID)
	}
	if d.ControlPlane == "" {
		return fmt.Errorf("controlPlane must not be empty")
	}
	if !strings.HasPrefix(d.ControlPlane, "http://") && !strings.HasPrefix(d.ControlPlane, "https://") {
		return fmt.Errorf("controlPlane %q must be an http(s) URL", d.ControlPlane)
	}
	if !decimalPattern.MatchString(d.Nonce) {
		return fmt.Errorf("nonce %q must be a decimal string with no leading zeros", d.Nonce)
	}
	if n, ok := new(big.Int).SetString(d.Nonce, 10); !ok || n.Cmp(maxUint256) > 0 {
		return fmt.Errorf("nonce %q does not fit in uint256", d.Nonce)
	}
	if _, err := d.IssuedAtTime(); err != nil {
		return err
	}
	if _, err := d.ExpiresAtTime(); err != nil {
		return err
	}
	return nil
}

// rfc3339UTC parses a strict RFC 3339 UTC timestamp. It rejects offsets other
// than "Z" so two clients cannot render the same instant differently and produce
// documents that hash differently but mean the same thing.
func rfc3339UTC(field, v string) (time.Time, error) {
	if !strings.HasSuffix(v, "Z") {
		return time.Time{}, fmt.Errorf("%s %q must be UTC with a Z suffix", field, v)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q is not RFC 3339: %w", field, v, err)
	}
	if t.Truncate(time.Second) != t {
		return time.Time{}, fmt.Errorf("%s %q must have second precision", field, v)
	}
	return t.UTC(), nil
}

// IssuedAtTime parses IssuedAt.
func (d *Document) IssuedAtTime() (time.Time, error) { return rfc3339UTC("issuedAt", d.IssuedAt) }

// ExpiresAtTime parses ExpiresAt.
func (d *Document) ExpiresAtTime() (time.Time, error) { return rfc3339UTC("expiresAt", d.ExpiresAt) }

// NonceInt returns the nonce as a big.Int for EIP-712 encoding.
func (d *Document) NonceInt() (*big.Int, error) {
	n, ok := new(big.Int).SetString(d.Nonce, 10)
	if !ok {
		return nil, fmt.Errorf("nonce %q is not a decimal integer", d.Nonce)
	}
	return n, nil
}

// AgentIDInt returns the agent id as a big.Int for EIP-712 encoding.
func (d *Document) AgentIDInt() (*big.Int, error) {
	n, ok := new(big.Int).SetString(d.AgentID, 10)
	if !ok {
		return nil, fmt.Errorf("agentId %q is not a decimal integer", d.AgentID)
	}
	return n, nil
}

// CAID returns the Canonical Agent Identifier, "{agentRegistry}/{agentId}".
//
// Derived rather than carried, so a document cannot assert a CAID inconsistent
// with its own fields.
func (d *Document) CAID() string {
	return d.AgentRegistry + "/" + d.AgentID
}

// Canonicalize returns the RFC 8785 (JCS) canonical JSON form of the document.
//
// Both signatures are computed over this, so it MUST be deterministic across
// implementations and languages.
func (d *Document) Canonicalize() ([]byte, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal document: %w", err)
	}
	// Round-trip through a generic map so key ordering comes from JCS rules
	// rather than from Go struct field order, which is not a stable contract.
	var generic map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("normalize document: %w", err)
	}
	return CanonicalJSON(generic)
}

// Parse decodes and structurally validates a binding document.
//
// It rejects unknown fields: a verifier that silently ignored an extra field
// would hash bytes the signer never intended to commit to.
func Parse(data []byte) (*Document, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("decode binding document: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}
