package binding

import (
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// EIP-712 constants for the MeshBinding proof (SPECIFICATION.md 4.4).
const (
	eip712DomainName    = "SATM"
	eip712DomainVersion = "1"

	meshBindingTypeString = "MeshBinding(uint256 agentId,string peerId,string sidecarKey," +
		"string meshId,string controlPlane,bytes32 documentHash,uint256 nonce,uint256 deadline)"

	eip712DomainTypeString = "EIP712Domain(string name,string version,uint256 chainId," +
		"address verifyingContract)"
)

func keccak(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// DomainParams are the EIP-712 domain fields.
//
// These come from the broker's ALLOW-LISTED registry tuple, never from the
// binding document. That is the whole point of check B2a: if the domain were
// taken from the document, an attacker could deploy their own ERC-8004-shaped
// registry, name it in the document, and have their signature verified against a
// domain of their own choosing. Every other check would pass. See threat TH-3a.
type DomainParams struct {
	ChainID           *big.Int
	VerifyingContract [20]byte
}

// domainSeparator computes the EIP-712 domainSeparator.
func (d DomainParams) domainSeparator() [32]byte {
	typeHash := keccak([]byte(eip712DomainTypeString))
	nameHash := keccak([]byte(eip712DomainName))
	versionHash := keccak([]byte(eip712DomainVersion))

	var buf []byte
	buf = append(buf, typeHash[:]...)
	buf = append(buf, nameHash[:]...)
	buf = append(buf, versionHash[:]...)
	buf = append(buf, leftPad32(d.ChainID.Bytes())...)
	buf = append(buf, leftPad32(d.VerifyingContract[:])...)
	return keccak(buf)
}

// leftPad32 left-pads to the 32-byte EIP-712 word size.
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// MeshBindingDigest computes the EIP-712 digest the agentWallet must sign.
//
// Exported so the CLI, the test vectors and the verifier all derive it the same
// way. A second implementation of this is a second chance to get the encoding
// subtly wrong.
//
// Note the value mapping (SPECIFICATION.md 4.4):
//   - agentId  <- uint256 parsed from the decimal string
//   - deadline <- expiresAt as unix seconds, and it MUST equal it exactly, so
//     the wallet signature cannot outlive the document it covers
//   - documentHash <- keccak256 of the canonical JSON, which transitively
//     commits to every field including ones not named in the typed struct
func MeshBindingDigest(doc *Document, domain DomainParams) ([32]byte, error) {
	agentID, err := doc.AgentIDInt()
	if err != nil {
		return [32]byte{}, err
	}
	nonce, err := doc.NonceInt()
	if err != nil {
		return [32]byte{}, err
	}
	expiresAt, err := doc.ExpiresAtTime()
	if err != nil {
		return [32]byte{}, err
	}
	canonical, err := doc.Canonicalize()
	if err != nil {
		return [32]byte{}, err
	}
	documentHash := keccak(canonical)

	typeHash := keccak([]byte(meshBindingTypeString))
	peerIDHash := keccak([]byte(doc.PeerID))
	sidecarKeyHash := keccak([]byte(doc.SidecarKey))
	meshIDHash := keccak([]byte(doc.MeshID))
	controlPlaneHash := keccak([]byte(doc.ControlPlane))
	deadline := big.NewInt(expiresAt.Unix())

	var structBuf []byte
	structBuf = append(structBuf, typeHash[:]...)
	structBuf = append(structBuf, leftPad32(agentID.Bytes())...)
	structBuf = append(structBuf, peerIDHash[:]...)
	structBuf = append(structBuf, sidecarKeyHash[:]...)
	structBuf = append(structBuf, meshIDHash[:]...)
	structBuf = append(structBuf, controlPlaneHash[:]...)
	structBuf = append(structBuf, documentHash[:]...)
	structBuf = append(structBuf, leftPad32(nonce.Bytes())...)
	structBuf = append(structBuf, leftPad32(deadline.Bytes())...)
	structHash := keccak(structBuf)

	sep := domain.domainSeparator()
	return keccak([]byte{0x19, 0x01}, sep[:], structHash[:]), nil
}

// VerifyWalletProof implements check B9: the holder of the on-chain agentWallet
// signed this exact document.
//
// expectedWallet is read FROM THE CHAIN (getAgentWallet) at check B7/B8, not from
// the document, so this function is verifying that the signature belongs to the
// wallet the registry currently reports.
//
// Only EOA (ECDSA secp256k1) signatures are handled here. ERC-1271 contract
// wallets require an on-chain isValidSignature call and are therefore dispatched
// by the verifier, which has a chain client; see Verifier.verifyWalletProof.
func VerifyWalletProof(doc *Document, domain DomainParams, expectedWallet [20]byte, signature []byte) error {
	digest, err := MeshBindingDigest(doc, domain)
	if err != nil {
		return denyf(ReasonMalformed, "B9", "compute digest: %v", err)
	}
	recovered, err := RecoverAddress(digest, signature)
	if err != nil {
		return denyf(ReasonWalletSignatureInvalid, "B9", "%v", err)
	}
	if recovered != expectedWallet {
		return denyf(ReasonWalletSignatureInvalid, "B9",
			"signature recovers to %s but the registry reports agentWallet %s",
			FormatAddress(recovered), FormatAddress(expectedWallet))
	}
	return nil
}

// FormatAddress renders a 20-byte address as lowercase 0x hex.
//
// Lowercase, not EIP-55: SAM label matching is exact and case-sensitive, so a
// checksummed address in one place and a lowercase one in another silently fails
// to match with no error message. See threat TH-18.
func FormatAddress(a [20]byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 2+40)
	out[0], out[1] = '0', 'x'
	for i, b := range a {
		out[2+i*2] = hexDigits[b>>4]
		out[3+i*2] = hexDigits[b&0x0f]
	}
	return string(out)
}

// ParseAddress parses a lowercase 0x-prefixed 20-byte hex address.
func ParseAddress(s string) ([20]byte, error) {
	var a [20]byte
	if !addrPattern.MatchString(s) {
		return a, fmt.Errorf("address %q must be lowercase 0x-prefixed 20-byte hex", s)
	}
	for i := 0; i < 20; i++ {
		hi, err := hexVal(s[2+i*2])
		if err != nil {
			return a, err
		}
		lo, err := hexVal(s[3+i*2])
		if err != nil {
			return a, err
		}
		a[i] = hi<<4 | lo
	}
	return a, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit %q", string(c))
	}
}

// ParseCAIP splits a CAIP tuple into its namespace, chain id and address.
func ParseCAIP(tuple string) (namespace string, chainID *big.Int, addr [20]byte, err error) {
	parts := strings.Split(tuple, ":")
	if len(parts) != 3 {
		return "", nil, addr, fmt.Errorf("registry tuple %q must have three colon-separated parts", tuple)
	}
	id, ok := new(big.Int).SetString(parts[1], 10)
	if !ok {
		return "", nil, addr, fmt.Errorf("chain id %q is not a decimal integer", parts[1])
	}
	addr, err = ParseAddress(parts[2])
	if err != nil {
		return "", nil, addr, err
	}
	return parts[0], id, addr, nil
}

// erc1271MagicValue is the return value of a successful isValidSignature call.
var erc1271MagicValue = [4]byte{0x16, 0x26, 0xba, 0x7e}

// erc1271Calldata builds calldata for isValidSignature(bytes32,bytes).
func erc1271Calldata(digest [32]byte, signature []byte) []byte {
	selector := keccak([]byte("isValidSignature(bytes32,bytes)"))
	out := make([]byte, 0, 4+32+32+32+len(signature)+32)
	out = append(out, selector[:4]...)
	out = append(out, digest[:]...)
	// offset to the dynamic `bytes` argument: two head words
	out = append(out, leftPad32(big.NewInt(64).Bytes())...)
	out = append(out, leftPad32(big.NewInt(int64(len(signature))).Bytes())...)
	out = append(out, signature...)
	// right-pad the payload to a 32-byte boundary
	if rem := len(signature) % 32; rem != 0 {
		out = append(out, make([]byte, 32-rem)...)
	}
	return out
}
