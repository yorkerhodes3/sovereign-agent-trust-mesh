package binding

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// The suite below follows SPECIFICATION.md 4.6: ONE test per check, each proving
// denial in isolation. That structure is deliberate -- it means a reader can go
// from a failing test name straight to the numbered check it defends, and it
// makes "did we actually implement B9a?" answerable rather than a matter of
// reading the verifier top to bottom.

const (
	testMeshID       = "satm-test"
	testControlPlane = "https://cp.satm.test"
	testRegistry     = "eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e"
)

// fixture is a complete, VALID binding plus everything needed to verify it.
// Each test mutates exactly one thing and asserts the corresponding denial, so a
// failure localises to a single check rather than to "something in setup".
type fixture struct {
	t *testing.T

	verifier *Verifier
	chain    *fakeChain
	fetcher  *fakeFetcher
	store    *memStore
	registry TrustedRegistry
	now      time.Time

	doc        *Document
	peerPub    []byte
	peerPriv   libp2pcrypto.PrivKey
	walletPriv *secp256k1.PrivateKey
	wallet     [20]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	reg, err := ParseTrustedRegistry(testRegistry)
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}

	// libp2p host key. Ed25519 is required by check B4.
	priv, pub, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	pubBytes, err := libp2pcrypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal host key: %v", err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}

	// agentWallet: a secp256k1 EOA.
	wpriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate wallet key: %v", err)
	}
	wallet := addressFromPriv(wpriv)

	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	sidecarPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sidecar key: %v", err)
	}

	doc, err := NewDocument(
		reg.Tuple, big.NewInt(42), wallet,
		pid.String(), "ed25519:"+base58Encode(sidecarPub),
		testMeshID, testControlPlane,
		now.Add(-time.Minute), 24*time.Hour,
	)
	if err != nil {
		t.Fatalf("build document: %v", err)
	}

	chain := newFakeChain()
	chain.put(reg.Address, big.NewInt(42), &fakeAgent{
		owner:  wallet,
		wallet: wallet,
		uri:    "ipfs://agent-42",
	})

	fetcher := newFakeFetcher()
	fetcher.put("ipfs://agent-42", validRegistrationFile(pid.String(), testMeshID, reg.Tuple, "42"))

	store := newMemStore()

	v, err := NewVerifier(Config{
		MeshID:                   testMeshID,
		ControlPlane:             testControlPlane,
		MaxTTL:                   168 * time.Hour,
		ClockSkew:                time.Minute,
		TrustedRegistries:        []TrustedRegistry{reg},
		RequireUniqueAgentWallet: true,
		Now:                      fixedClock(now),
	}, chain, fetcher, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	return &fixture{
		t: t, verifier: v, chain: chain, fetcher: fetcher, store: store,
		registry: reg, now: now, doc: doc,
		peerPub: pubBytes, peerPriv: priv, walletPriv: wpriv, wallet: wallet,
	}
}

// input signs the current document with both keys and returns a submission.
func (f *fixture) input() Input {
	f.t.Helper()
	return Input{
		Document:        f.docBytes(),
		PeerPublicKey:   f.peerPub,
		PeerSignature:   f.signPeer(),
		WalletSignature: f.signWallet(),
	}
}

func (f *fixture) docBytes() []byte {
	f.t.Helper()
	b, err := json.Marshal(f.doc)
	if err != nil {
		f.t.Fatalf("marshal doc: %v", err)
	}
	return b
}

func (f *fixture) signPeer() []byte {
	f.t.Helper()
	digest, err := PeerSigningDigest(f.doc)
	if err != nil {
		f.t.Fatalf("peer digest: %v", err)
	}
	sig, err := f.peerPriv.Sign(digest[:])
	if err != nil {
		f.t.Fatalf("peer sign: %v", err)
	}
	return sig
}

func (f *fixture) domain() DomainParams {
	return DomainParams{ChainID: f.registry.ChainID, VerifyingContract: f.registry.Address}
}

func (f *fixture) signWallet() []byte {
	f.t.Helper()
	return f.signWalletWith(f.walletPriv, f.domain())
}

func (f *fixture) signWalletWith(priv *secp256k1.PrivateKey, domain DomainParams) []byte {
	f.t.Helper()
	digest, err := MeshBindingDigest(f.doc, domain)
	if err != nil {
		f.t.Fatalf("mesh binding digest: %v", err)
	}
	compact := dcrecdsa.SignCompact(priv, digest[:], false)
	// dcrec emits [V||R||S] with V in 27..30; the wire format is [R||S||V].
	sig := make([]byte, 65)
	copy(sig[0:64], compact[1:65])
	sig[64] = compact[0]
	return sig
}

func (f *fixture) verify() (*Result, error) {
	return f.verifier.Verify(context.Background(), f.input())
}

// assertDenied asserts the verification failed with a specific reason code.
func assertDenied(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected denial %q, got success", want)
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("expected *binding.Error, got %T: %v", err, err)
	}
	if be.Reason != want {
		t.Fatalf("expected reason %q, got %q (%v)", want, be.Reason, err)
	}
}

// --------------------------------------------------------- happy path ------

func TestVerify_ValidBindingSucceeds(t *testing.T) {
	f := newFixture(t)
	res, err := f.verify()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if res.Record.CAID != testRegistry+"/42" {
		t.Errorf("CAID = %q", res.Record.CAID)
	}
	if res.Record.PeerID != f.doc.PeerID {
		t.Errorf("PeerID = %q", res.Record.PeerID)
	}
	if f.store.count() != 1 {
		t.Errorf("expected 1 committed record, got %d", f.store.count())
	}
}

// --------------------------------------------------------- B1 freshness ----

func TestVerify_B1_RejectsExpiredDocument(t *testing.T) {
	f := newFixture(t)
	f.doc.IssuedAt = f.now.Add(-48 * time.Hour).Format(time.RFC3339)
	f.doc.ExpiresAt = f.now.Add(-24 * time.Hour).Format(time.RFC3339)
	_, err := f.verify()
	assertDenied(t, err, ReasonExpired)
}

func TestVerify_B1_RejectsFutureDocument(t *testing.T) {
	f := newFixture(t)
	f.doc.IssuedAt = f.now.Add(time.Hour).Format(time.RFC3339)
	f.doc.ExpiresAt = f.now.Add(25 * time.Hour).Format(time.RFC3339)
	_, err := f.verify()
	assertDenied(t, err, ReasonNotYetValid)
}

// TestVerify_B1_RejectsOverlongTTL is the check that stops a signer minting a
// binding that outlives nonce retention and becomes replayable.
func TestVerify_B1_RejectsOverlongTTL(t *testing.T) {
	f := newFixture(t)
	f.doc.IssuedAt = f.now.Add(-time.Minute).Format(time.RFC3339)
	f.doc.ExpiresAt = f.now.Add(10 * 365 * 24 * time.Hour).Format(time.RFC3339)
	_, err := f.verify()
	assertDenied(t, err, ReasonTTLTooLong)
}

func TestVerify_B1_RejectsNonUTCTimestamp(t *testing.T) {
	f := newFixture(t)
	f.doc.IssuedAt = "2026-08-23T08:00:00-04:00" // same instant, different bytes
	_, err := f.verify()
	assertDenied(t, err, ReasonMalformed)
}

// --------------------------------------------------------- B2 mesh ---------

func TestVerify_B2_RejectsWrongMesh(t *testing.T) {
	f := newFixture(t)
	f.doc.MeshID = "satm-prod"
	_, err := f.verify()
	assertDenied(t, err, ReasonWrongMesh)
}

func TestVerify_B2_RejectsWrongControlPlane(t *testing.T) {
	f := newFixture(t)
	f.doc.ControlPlane = "https://evil.example"
	_, err := f.verify()
	assertDenied(t, err, ReasonWrongControlPlane)
}

// --------------------------------------------------------- B2a registry ----

// TestVerify_B2a_RejectsAttackerDeployedRegistry is threat TH-3a and negative
// control N-11.
//
// The attacker deploys their own ERC-8004-shaped contract, mints themselves
// agentId 42 with a wallet they control, publishes a matching registration file,
// and signs both proofs correctly. The submission is INTERNALLY CONSISTENT --
// every other check would pass. Only the allow-list stops it.
func TestVerify_B2a_RejectsAttackerDeployedRegistry(t *testing.T) {
	f := newFixture(t)
	evil := "eip155:84532:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	evilReg, err := ParseTrustedRegistry(evil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Attacker's registry is fully populated and self-consistent.
	f.chain.put(evilReg.Address, big.NewInt(42), &fakeAgent{
		owner: f.wallet, wallet: f.wallet, uri: "ipfs://evil-42",
	})
	f.fetcher.put("ipfs://evil-42", validRegistrationFile(f.doc.PeerID, testMeshID, evil, "42"))
	f.doc.AgentRegistry = evil

	_, err = f.verify()
	assertDenied(t, err, ReasonRegistryNotAllowed)
}

// TestVerify_B2a_DomainIsDerivedFromAllowlistNotDocument proves the second half
// of the B2a defence: even for an allow-listed registry, the EIP-712 domain is
// OURS. A signature made against a different domain must not verify.
func TestVerify_B2a_DomainIsDerivedFromAllowlistNotDocument(t *testing.T) {
	f := newFixture(t)
	wrongDomain := DomainParams{
		ChainID:           big.NewInt(1), // mainnet, not 84532
		VerifyingContract: f.registry.Address,
	}
	in := Input{
		Document:        f.docBytes(),
		PeerPublicKey:   f.peerPub,
		PeerSignature:   f.signPeer(),
		WalletSignature: f.signWalletWith(f.walletPriv, wrongDomain),
	}
	_, err := f.verifier.Verify(context.Background(), in)
	assertDenied(t, err, ReasonWalletSignatureInvalid)
}

func TestNewVerifier_RejectsEmptyAllowlist(t *testing.T) {
	_, err := NewVerifier(Config{
		MeshID: "m", ControlPlane: "https://cp", MaxTTL: time.Hour,
	}, newFakeChain(), newFakeFetcher(), newMemStore())
	if err == nil {
		t.Fatal("expected an empty registry allow-list to be rejected at construction")
	}
	if !strings.Contains(err.Error(), "trusted registry") {
		t.Errorf("error should explain the allow-list requirement, got: %v", err)
	}
}

// --------------------------------------------------------- B3/B15 nonce ----

func TestVerify_B3_RejectsReplayedNonce(t *testing.T) {
	f := newFixture(t)
	if _, err := f.verify(); err != nil {
		t.Fatalf("first submission: %v", err)
	}
	// Resubmitting the identical document must fail on the nonce, not on
	// anything downstream.
	_, err := f.verify()
	assertDenied(t, err, ReasonNonceReused)
}

// TestVerify_B15_ConcurrentSubmissionsCommitExactlyOnce proves the check/consume
// split is genuinely atomic. Both goroutines pass B3 (neither has committed
// yet); exactly one must survive B15.
func TestVerify_B15_ConcurrentSubmissionsCommitExactlyOnce(t *testing.T) {
	f := newFixture(t)
	in := f.input()

	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			_, err := f.verifier.Verify(context.Background(), in)
			results[idx] = err
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
			continue
		}
		if r := ReasonOf(err); r != ReasonNonceReused {
			t.Errorf("unexpected failure reason %q: %v", r, err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success out of %d, got %d", n, successes)
	}
	if f.store.count() != 1 {
		t.Fatalf("expected exactly 1 committed record, got %d", f.store.count())
	}
}

// TestVerify_TH17_UnsignedSubmissionCannotBurnANonce proves the DoS defence: a
// caller who cannot produce valid signatures must not be able to consume a nonce
// they do not own.
func TestVerify_TH17_UnsignedSubmissionCannotBurnANonce(t *testing.T) {
	f := newFixture(t)
	bad := f.input()
	bad.PeerSignature = make([]byte, 64) // garbage

	if _, err := f.verifier.Verify(context.Background(), bad); err == nil {
		t.Fatal("expected the forged submission to be denied")
	}
	// The legitimate holder can still use the nonce.
	if _, err := f.verify(); err != nil {
		t.Fatalf("nonce was burned by a failed submission: %v", err)
	}
}

// --------------------------------------------------------- B4/B5 peer ------

func TestVerify_B4_RejectsKeyThatDoesNotDeriveClaimedPeerID(t *testing.T) {
	f := newFixture(t)
	_, otherPub, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	otherBytes, _ := libp2pcrypto.MarshalPublicKey(otherPub)

	in := f.input()
	in.PeerPublicKey = otherBytes
	_, err = f.verifier.Verify(context.Background(), in)
	assertDenied(t, err, ReasonPeerKeyMismatch)
}

func TestVerify_B4_RejectsNonEd25519HostKey(t *testing.T) {
	priv, pub, err := libp2pcrypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate secp256k1: %v", err)
	}
	f := newFixture(t)
	pubBytes, _ := libp2pcrypto.MarshalPublicKey(pub)
	pid, _ := peer.IDFromPublicKey(pub)
	f.doc.PeerID = pid.String()
	f.peerPriv = priv
	f.peerPub = pubBytes

	_, err = f.verify()
	assertDenied(t, err, ReasonPeerKeyMismatch)
}

func TestVerify_B5_RejectsInvalidPeerSignature(t *testing.T) {
	f := newFixture(t)
	in := f.input()
	in.PeerSignature[0] ^= 0xff
	_, err := f.verifier.Verify(context.Background(), in)
	assertDenied(t, err, ReasonPeerSignatureInvalid)
}

// TestVerify_B5_SignatureDoesNotSurviveDocumentMutation is the substitution
// defence: the signature covers the canonical document, so changing ANY field
// after signing invalidates it.
func TestVerify_B5_SignatureDoesNotSurviveDocumentMutation(t *testing.T) {
	f := newFixture(t)
	in := f.input()

	f.doc.AgentID = "43"
	f.chain.put(f.registry.Address, big.NewInt(43), &fakeAgent{
		owner: f.wallet, wallet: f.wallet, uri: "ipfs://agent-43",
	})
	f.fetcher.put("ipfs://agent-43", validRegistrationFile(f.doc.PeerID, testMeshID, f.registry.Tuple, "43"))
	in.Document = f.docBytes() // mutated body, original signatures

	_, err := f.verifier.Verify(context.Background(), in)
	assertDenied(t, err, ReasonPeerSignatureInvalid)
}

// --------------------------------------------------------- B6/B7/B8 chain --

func TestVerify_B6_RejectsUnknownAgent(t *testing.T) {
	f := newFixture(t)
	f.chain.put(f.registry.Address, big.NewInt(42), &fakeAgent{missing: true})
	_, err := f.verify()
	assertDenied(t, err, ReasonAgentNotFound)
}

// TestVerify_B7_RejectsClearedAgentWallet is the transferred-agent case: ERC-8004
// zeroes agentWallet on ERC-721 transfer, which is what makes a sold agent's
// binding fail with no SATM-specific bookkeeping (threat TH-5).
func TestVerify_B7_RejectsClearedAgentWallet(t *testing.T) {
	f := newFixture(t)
	a := f.chain.get(f.registry.Address, big.NewInt(42))
	a.wallet = [20]byte{} // simulate transfer
	_, err := f.verify()
	assertDenied(t, err, ReasonWalletUnset)
}

func TestVerify_B8_RejectsWalletMismatch(t *testing.T) {
	f := newFixture(t)
	other, _ := secp256k1.GeneratePrivateKey()
	a := f.chain.get(f.registry.Address, big.NewInt(42))
	a.wallet = addressFromPriv(other)
	_, err := f.verify()
	assertDenied(t, err, ReasonWalletMismatch)
}

func TestVerify_B6_ReportsChainUnavailable(t *testing.T) {
	f := newFixture(t)
	f.chain.failOwnerOf = true
	_, err := f.verify()
	assertDenied(t, err, ReasonChainUnavailable)
}

// --------------------------------------------------------- B9 wallet ------

// TestVerify_B9_RejectsSignatureFromWrongWallet is threat TH-1: an impostor
// claiming another agent's identity to inherit its reputation. They control the
// PeerID but not the agentWallet.
func TestVerify_B9_RejectsSignatureFromWrongWallet(t *testing.T) {
	f := newFixture(t)
	impostor, _ := secp256k1.GeneratePrivateKey()
	in := Input{
		Document:        f.docBytes(),
		PeerPublicKey:   f.peerPub,
		PeerSignature:   f.signPeer(),
		WalletSignature: f.signWalletWith(impostor, f.domain()),
	}
	_, err := f.verifier.Verify(context.Background(), in)
	assertDenied(t, err, ReasonWalletSignatureInvalid)
}

func TestVerify_B9_AcceptsERC1271ContractWallet(t *testing.T) {
	f := newFixture(t)
	digest, err := MeshBindingDigest(f.doc, f.domain())
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	f.chain.allowERC1271(f.wallet, digest)

	in := Input{
		Document:      f.docBytes(),
		PeerPublicKey: f.peerPub,
		PeerSignature: f.signPeer(),
		// A contract-wallet signature is opaque bytes, not a recoverable ECDSA
		// signature, so EOA recovery must fail and ERC-1271 must be consulted.
		WalletSignature: []byte("safe-wallet-opaque-signature-blob"),
	}
	if _, err := f.verifier.Verify(context.Background(), in); err != nil {
		t.Fatalf("expected ERC-1271 acceptance, got %v", err)
	}
}

// TestRecoverAddress_RejectsHighS guards against signature malleability: for
// every valid (r,s) there is an equally valid (r,n-s), and accepting both gives
// one authorisation two encodings.
func TestRecoverAddress_RejectsHighS(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	digest := [32]byte{1, 2, 3}
	compact := dcrecdsa.SignCompact(priv, digest[:], false)

	sig := make([]byte, 65)
	copy(sig[0:64], compact[1:65])
	sig[64] = compact[0]

	// Flip s to n-s, which is the other valid signature for the same message.
	s := new(big.Int).SetBytes(sig[32:64])
	highS := new(big.Int).Sub(secp256k1.S256().N, s)
	copy(sig[32:64], leftPad32(highS.Bytes()))

	if _, err := RecoverAddress(digest, sig); err == nil {
		t.Fatal("expected high-s signature to be rejected")
	}
}

// --------------------------------------------------------- B9a wallet ------

// TestVerify_B9a_RejectsWalletAlreadyBoundToAnotherAgent is threat TH-5b: two
// agents sharing an agentWallet would silently share ERC-8226 mandates and caps,
// because RAMS keys mandates by (agent, principal).
func TestVerify_B9a_RejectsWalletAlreadyBoundToAnotherAgent(t *testing.T) {
	f := newFixture(t)
	if _, err := f.verify(); err != nil {
		t.Fatalf("first binding: %v", err)
	}

	// A second agent, same wallet.
	f.chain.put(f.registry.Address, big.NewInt(99), &fakeAgent{
		owner: f.wallet, wallet: f.wallet, uri: "ipfs://agent-99",
	})
	f.fetcher.put("ipfs://agent-99", validRegistrationFile(f.doc.PeerID, testMeshID, f.registry.Tuple, "99"))
	f.doc.AgentID = "99"
	nonce, _ := NewNonce()
	f.doc.Nonce = nonce

	_, err := f.verify()
	assertDenied(t, err, ReasonWalletBoundElsewhere)
}

// --------------------------------------------------------- B10..B13 file ---

func TestVerify_B10_RejectsUnreachableRegistrationFile(t *testing.T) {
	f := newFixture(t)
	f.fetcher.err = errors.New("ipfs timeout")
	_, err := f.verify()
	assertDenied(t, err, ReasonRegistrationUnreachable)
}

func TestVerify_B11_RejectsFileNamingADifferentAgent(t *testing.T) {
	f := newFixture(t)
	f.fetcher.put("ipfs://agent-42",
		validRegistrationFile(f.doc.PeerID, testMeshID, f.registry.Tuple, "999"))
	_, err := f.verify()
	assertDenied(t, err, ReasonRegistrationMismatch)
}

func TestVerify_B12_RejectsFileNotAdvertisingThisPeer(t *testing.T) {
	f := newFixture(t)
	other := "12D3KooWA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2"
	f.fetcher.put("ipfs://agent-42",
		validRegistrationFile(other, testMeshID, f.registry.Tuple, "42"))
	_, err := f.verify()
	assertDenied(t, err, ReasonSAMEndpointMissing)
}

// TestVerify_B12_RejectsFileAdvertisingADifferentMesh: a file advertising the
// right PeerID on another mesh is not evidence for a binding on this one.
func TestVerify_B12_RejectsFileAdvertisingADifferentMesh(t *testing.T) {
	f := newFixture(t)
	f.fetcher.put("ipfs://agent-42",
		validRegistrationFile(f.doc.PeerID, "satm-prod", f.registry.Tuple, "42"))
	_, err := f.verify()
	assertDenied(t, err, ReasonSAMEndpointMissing)
}

// TestVerify_B13_RejectsInactiveAgent also covers threat TH-16's sibling: an
// operator can decommission by flipping active to false.
func TestVerify_B13_RejectsInactiveAgent(t *testing.T) {
	f := newFixture(t)
	file := validRegistrationFile(f.doc.PeerID, testMeshID, f.registry.Tuple, "42")
	file.Active = false
	f.fetcher.put("ipfs://agent-42", file)
	_, err := f.verify()
	assertDenied(t, err, ReasonAgentInactive)
}

// --------------------------------------------------------- rotation --------

// TestVerify_RebindingRevokesThePriorBinding covers acceptance criterion A3:
// the same agentId resolves to a NEW PeerID after a key rotation, and the old
// binding does not linger.
func TestVerify_RebindingRevokesThePriorBinding(t *testing.T) {
	f := newFixture(t)
	if _, err := f.verify(); err != nil {
		t.Fatalf("initial binding: %v", err)
	}
	oldPeer := f.doc.PeerID

	// Node resets its identity: new host key, new PeerID, same agent.
	priv, pub, _ := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	pubBytes, _ := libp2pcrypto.MarshalPublicKey(pub)
	pid, _ := peer.IDFromPublicKey(pub)
	f.peerPriv, f.peerPub = priv, pubBytes
	f.doc.PeerID = pid.String()
	nonce, _ := NewNonce()
	f.doc.Nonce = nonce
	f.fetcher.put("ipfs://agent-42",
		validRegistrationFile(pid.String(), testMeshID, f.registry.Tuple, "42"))

	if _, err := f.verify(); err != nil {
		t.Fatalf("re-binding: %v", err)
	}
	if f.store.count() != 1 {
		t.Fatalf("expected the prior binding to be revoked, got %d active records", f.store.count())
	}
	if f.store.records[0].PeerID == oldPeer {
		t.Fatal("active record still points at the old PeerID")
	}
}

// --------------------------------------------------------- helpers ---------

func validRegistrationFile(peerID, meshID, registryTuple, agentID string) *RegistrationFile {
	return &RegistrationFile{
		Type:   RegistrationFileType,
		Name:   "Test Agent",
		Active: true,
		Services: []Service{
			{Name: "SAM", Endpoint: FormatSAMURI(peerID, meshID), Version: "v1alpha1"},
		},
		Registrations: []Registration{
			{AgentID: json.Number(agentID), AgentRegistry: registryTuple},
		},
	}
}

func addressFromPriv(priv *secp256k1.PrivateKey) [20]byte {
	pub := priv.PubKey().SerializeUncompressed()
	var addr [20]byte
	h := keccak(pub[1:])
	copy(addr[:], h[12:])
	return addr
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode is a small test helper for building plausible sidecar keys.
func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, radix, mod)
		out = append([]byte{base58Alphabet[mod.Int64()]}, out...)
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append([]byte{base58Alphabet[0]}, out...)
	}
	return string(out)
}
