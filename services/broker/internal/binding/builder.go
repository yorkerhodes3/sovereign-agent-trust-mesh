package binding

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// newRecordID generates an opaque binding record identifier.
func newRecordID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the process has no entropy source; there is
		// no sensible degraded mode for a security component.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return "bnd_" + hex.EncodeToString(b[:])
}

// NewNonce returns a fresh 256-bit nonce as a decimal string, matching the
// encoding the document requires.
func NewNonce() (string, error) {
	n, err := rand.Int(rand.Reader, maxUint256)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return n.String(), nil
}

// NewDocument assembles a binding document with correct encodings.
//
// Provided so callers (satm-cli, tests) cannot accidentally hand-roll a document
// with an EIP-55 address or an RFC 3339 offset, both of which would produce a
// structurally invalid document only at verification time.
func NewDocument(
	registryTuple string,
	agentID *big.Int,
	agentWallet [20]byte,
	peerID, sidecarKey, meshID, controlPlane string,
	issuedAt time.Time,
	ttl time.Duration,
) (*Document, error) {
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	doc := &Document{
		Type:          DocumentType,
		AgentRegistry: registryTuple,
		AgentID:       agentID.String(),
		AgentWallet:   FormatAddress(agentWallet),
		PeerID:        peerID,
		SidecarKey:    sidecarKey,
		MeshID:        meshID,
		ControlPlane:  controlPlane,
		Nonce:         nonce,
		IssuedAt:      issuedAt.Format(time.RFC3339),
		ExpiresAt:     issuedAt.Add(ttl).Format(time.RFC3339),
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

// ParseTrustedRegistry converts a CAIP tuple into a TrustedRegistry entry,
// rejecting anything that is not already canonical.
//
// Strictness here is deliberate: the allow-list is the root of the B2a defence,
// so a typo in configuration should fail at startup rather than silently
// failing to match at verification time and denying every legitimate binding.
func ParseTrustedRegistry(tuple string) (TrustedRegistry, error) {
	if !caipPattern.MatchString(tuple) {
		return TrustedRegistry{}, fmt.Errorf(
			"trusted registry %q must be a lowercase CAIP tuple "+
				"{namespace}:{chainId}:0x{40 lowercase hex}", tuple)
	}
	ns, chainID, addr, err := ParseCAIP(tuple)
	if err != nil {
		return TrustedRegistry{}, err
	}
	return TrustedRegistry{Tuple: tuple, Namespace: ns, ChainID: chainID, Address: addr}, nil
}
