package binding

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// secp256k1HalfN is n/2. Signatures with s above this are the "other" valid
// signature for the same message -- see RecoverAddress for why we reject them.
var secp256k1HalfN = new(big.Int).Rsh(secp256k1.S256().N, 1)

// RecoverAddress recovers the Ethereum address that produced an EIP-191/712
// style 65-byte [R || S || V] signature over digest.
//
// Two guards that are easy to omit and expensive to omit:
//
//  1. LOW-S ONLY. For every valid (r, s) there is an equally valid (r, n-s).
//     Accepting both means one authorisation has two distinct byte encodings,
//     which defeats any replay defence keyed on the signature bytes and is the
//     classic transaction-malleability bug. EIP-2 requires low-s on chain; we
//     enforce it off chain for the same reason.
//
//  2. V NORMALISATION. Wallets emit v as 27/28 (Ethereum convention) while the
//     raw recovery id is 0/1, and EIP-155 adds a chain-id offset. Accepting a
//     bare 0/1 as well as 27/28 keeps us compatible with both hardware wallets
//     and raw signing libraries without silently accepting nonsense.
func RecoverAddress(digest [32]byte, signature []byte) ([20]byte, error) {
	var addr [20]byte
	if len(signature) != 65 {
		return addr, fmt.Errorf("signature must be 65 bytes [R||S||V], got %d", len(signature))
	}

	r := new(big.Int).SetBytes(signature[0:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := signature[64]

	switch {
	case v == 27 || v == 28:
		v -= 27
	case v == 0 || v == 1:
		// already a raw recovery id
	default:
		return addr, fmt.Errorf("signature v must be 0, 1, 27 or 28, got %d", signature[64])
	}

	n := secp256k1.S256().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return addr, fmt.Errorf("signature r is out of range")
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return addr, fmt.Errorf("signature s is out of range")
	}
	if s.Cmp(secp256k1HalfN) > 0 {
		return addr, fmt.Errorf("signature has high s; only low-s (EIP-2) signatures are accepted")
	}

	// dcrec wants [V || R || S] with V in 27..30.
	compact := make([]byte, 65)
	compact[0] = v + 27
	copy(compact[1:33], leftPad32(r.Bytes()))
	copy(compact[33:65], leftPad32(s.Bytes()))

	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return addr, fmt.Errorf("cannot recover public key: %w", err)
	}

	// Ethereum address = last 20 bytes of keccak256(uncompressed pubkey, minus
	// the 0x04 prefix byte).
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	copy(addr[:], sum[12:])
	return addr, nil
}
