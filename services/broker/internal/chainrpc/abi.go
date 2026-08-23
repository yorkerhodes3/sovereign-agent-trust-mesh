// Package chainrpc implements the ChainClient port over plain JSON-RPC.
//
// The ABI surface SATM needs is tiny -- four view functions taking a uint256 or
// a (bytes32, bytes) pair -- so this package hand-rolls encoding rather than
// depending on go-ethereum. That keeps the broker's dependency tree small and,
// more importantly, keeps every byte the broker puts on the wire auditable in
// one short file.
package chainrpc

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Solidity signatures for the reads SATM performs. Selectors are DERIVED from
// these strings at call time rather than hard-coded, so a typo cannot silently
// produce a valid-looking call to the wrong function; selectorFor is pinned
// against known-good values in the tests.
const (
	sigOwnerOf          = "ownerOf(uint256)"
	sigGetAgentWallet   = "getAgentWallet(uint256)"
	sigTokenURI         = "tokenURI(uint256)"
	sigIsValidSignature = "isValidSignature(bytes32,bytes)"
)

// erc1271MagicValue is the bytes4 a contract wallet returns to accept a
// signature (EIP-1271). Anything else -- including a successful call returning
// zero -- is a rejection.
var erc1271MagicValue = [4]byte{0x16, 0x26, 0xba, 0x7e}

func keccak256(data ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// selectorFor returns the 4-byte function selector for a Solidity signature.
func selectorFor(sig string) []byte {
	sum := keccak256([]byte(sig))
	return sum[:4]
}

// padLeft32 renders a value right-aligned in a 32-byte word, the ABI layout for
// all fixed-size types.
func padLeft32(b []byte) []byte {
	if len(b) > 32 {
		panic("chainrpc: value wider than a 32-byte word")
	}
	word := make([]byte, 32)
	copy(word[32-len(b):], b)
	return word
}

// encodeUint256Call builds calldata for `f(uint256)`.
func encodeUint256Call(sig string, v *big.Int) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("nil uint256 argument")
	}
	if v.Sign() < 0 {
		return nil, fmt.Errorf("negative value %s cannot be a uint256", v)
	}
	if v.BitLen() > 256 {
		return nil, fmt.Errorf("value overflows uint256 (%d bits)", v.BitLen())
	}
	return append(selectorFor(sig), padLeft32(v.Bytes())...), nil
}

// encodeIsValidSignature builds calldata for `isValidSignature(bytes32,bytes)`.
//
// `bytes` is dynamic, so the head holds an OFFSET to the tail rather than the
// data itself -- getting this wrong is the classic hand-rolled-ABI bug, and it
// fails in the permissive direction (the wallet decodes garbage and may return
// the magic value), so it is worth being explicit.
func encodeIsValidSignature(digest [32]byte, sig []byte) []byte {
	out := selectorFor(sigIsValidSignature)
	out = append(out, digest[:]...)

	// Head is two words: the digest above and this offset. The tail therefore
	// starts at byte 64 of the argument block.
	out = append(out, padLeft32(big.NewInt(64).Bytes())...)

	// Tail: length, then the payload padded up to a 32-byte boundary.
	out = append(out, padLeft32(big.NewInt(int64(len(sig))).Bytes())...)
	out = append(out, sig...)
	if rem := len(sig) % 32; rem != 0 {
		out = append(out, make([]byte, 32-rem)...)
	}
	return out
}

// decodeAddress reads a single `address` return value.
func decodeAddress(data []byte) ([20]byte, error) {
	var out [20]byte
	if len(data) != 32 {
		return out, fmt.Errorf("expected a 32-byte word for address, got %d bytes", len(data))
	}
	// The high 12 bytes MUST be zero. A non-zero prefix means the callee did not
	// actually return an address, and silently truncating would let a hostile or
	// misconfigured contract steer us to an attacker-chosen account.
	for _, b := range data[:12] {
		if b != 0 {
			return out, fmt.Errorf("address word has non-zero padding: %s", hex.EncodeToString(data))
		}
	}
	copy(out[:], data[12:])
	return out, nil
}

// decodeBytes4 reads a single `bytes4` return value, which is LEFT-aligned.
func decodeBytes4(data []byte) ([4]byte, error) {
	var out [4]byte
	if len(data) != 32 {
		return out, fmt.Errorf("expected a 32-byte word for bytes4, got %d bytes", len(data))
	}
	copy(out[:], data[:4])
	return out, nil
}

// decodeString reads a single dynamic `string` return value.
//
// Every length and offset here comes from a remote node, so each is bounds-
// checked against the actual buffer before use.
func decodeString(data []byte, maxLen int) (string, error) {
	if len(data) < 64 {
		return "", fmt.Errorf("string return too short: %d bytes", len(data))
	}
	offset := new(big.Int).SetBytes(data[:32])
	if !offset.IsInt64() {
		return "", fmt.Errorf("string offset overflows int64")
	}
	off := offset.Int64()
	if off < 0 || off+32 > int64(len(data)) {
		return "", fmt.Errorf("string offset %d out of bounds (buffer %d)", off, len(data))
	}

	length := new(big.Int).SetBytes(data[off : off+32])
	if !length.IsInt64() {
		return "", fmt.Errorf("string length overflows int64")
	}
	n := length.Int64()
	if n < 0 || off+32+n > int64(len(data)) {
		return "", fmt.Errorf("string length %d out of bounds (buffer %d)", n, len(data))
	}
	if maxLen > 0 && n > int64(maxLen) {
		return "", fmt.Errorf("string of %d bytes exceeds the %d-byte limit", n, maxLen)
	}
	return string(data[off+32 : off+32+n]), nil
}

// ------------------------------------------------------------- hex helpers --

func hexEncode(b []byte) string { return "0x" + hex.EncodeToString(b) }

// hexDecode parses a 0x-prefixed hex string from an RPC response.
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		// Quantities may be returned odd-length; data never should be, but pad
		// rather than fail so a lenient node does not break an honest read.
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func addressHex(a [20]byte) string { return hexEncode(a[:]) }
