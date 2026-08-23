package binding

import (
	"crypto/sha256"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// VerifyPeerProof implements checks B4 and B5: the node controls the libp2p
// private key for the PeerID it claims.
//
// pubKeyBytes is the PROTOBUF-marshalled public key (crypto.MarshalPublicKey),
// matching what SAM itself puts on the wire in BootstrapEnrollRequest.public_key.
//
// B4 is subtler than it looks. The obvious implementation --
// "multihash the raw key bytes and compare" -- is WRONG, and wrong in the
// dangerous direction: it would accept keys that do not actually produce the
// claimed PeerID. libp2p's real derivation is
//
//	PeerID = multihash(protobuf(pubkey))
//
// using the *identity* multihash function when the serialised key is <= 42 bytes
// and sha2-256 otherwise. peer.IDFromPublicKey implements exactly that, so we
// delegate rather than reimplement. SPECIFICATION.md 4.4 makes this normative.
//
// The signature (B5) is over SHA-256 of the canonical document. Ed25519 in Go
// hashes internally, but we sign a digest rather than the raw document so that
// the signing payload is a fixed 32 bytes regardless of document size, and so
// the same digest can be logged and compared without retaining the full document.
func VerifyPeerProof(doc *Document, pubKeyBytes, signature []byte) error {
	pub, err := crypto.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return denyf(ReasonPeerKeyMismatch, "B4",
			"public key is not a valid libp2p protobuf key: %v", err)
	}

	// For the prototype, host keys MUST be Ed25519. This is a deliberate
	// narrowing: it makes derivation deterministic (the identity-multihash path
	// always applies) and avoids inheriting the malleability and
	// key-recovery quirks of the other supported curves.
	if pub.Type() != crypto.Ed25519 {
		return denyf(ReasonPeerKeyMismatch, "B4",
			"host key must be Ed25519, got %s", pub.Type())
	}

	// B4: does this key actually produce the claimed PeerID?
	derived, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return denyf(ReasonPeerKeyMismatch, "B4", "cannot derive peer id from key: %v", err)
	}
	claimed, err := peer.Decode(doc.PeerID)
	if err != nil {
		return denyf(ReasonPeerKeyMismatch, "B4", "peerId %q is not decodable: %v", doc.PeerID, err)
	}
	if derived != claimed {
		return denyf(ReasonPeerKeyMismatch, "B4",
			"public key derives peer id %s, document claims %s", derived, claimed)
	}

	// B5: is the signature over this exact document valid under that key?
	canonical, err := doc.Canonicalize()
	if err != nil {
		return denyf(ReasonMalformed, "B5", "canonicalize: %v", err)
	}
	digest := sha256.Sum256(canonical)

	ok, err := pub.Verify(digest[:], signature)
	if err != nil {
		return denyf(ReasonPeerSignatureInvalid, "B5", "signature verification error: %v", err)
	}
	if !ok {
		return denyf(ReasonPeerSignatureInvalid, "B5",
			"signature does not verify under the peer's host key")
	}
	return nil
}

// PeerSigningDigest returns the 32-byte digest a node must sign with its libp2p
// host key. Exported so `satm-cli bind` and the test vectors compute it the same
// way the verifier does, rather than each side reimplementing the recipe.
func PeerSigningDigest(doc *Document) ([32]byte, error) {
	canonical, err := doc.Canonicalize()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}
