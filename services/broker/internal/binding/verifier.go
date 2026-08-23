package binding

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ChainClient is the narrow slice of ERC-8004 the verifier reads.
//
// Deliberately minimal and read-only: SATM never writes to the identity
// registry, and a narrow interface makes that constraint enforceable at compile
// time rather than by convention. It also keeps the verifier testable without an
// RPC endpoint.
type ChainClient interface {
	// OwnerOf returns the ERC-721 owner. Returns ErrAgentNotFound if the token
	// does not exist.
	OwnerOf(ctx context.Context, registry [20]byte, agentID *big.Int) ([20]byte, error)

	// GetAgentWallet returns the ERC-8004 reserved `agentWallet` metadata value.
	// It is the zero address after an ERC-721 transfer -- the behaviour SATM's
	// revocation story depends on (see SPECIFICATION.md 7.3.2).
	GetAgentWallet(ctx context.Context, registry [20]byte, agentID *big.Int) ([20]byte, error)

	// AgentURI returns tokenURI, which resolves to the registration file.
	AgentURI(ctx context.Context, registry [20]byte, agentID *big.Int) (string, error)

	// IsValidERC1271Signature performs a staticcall to isValidSignature for
	// smart-contract wallets (Safe, EIP-7702 delegated accounts).
	IsValidERC1271Signature(ctx context.Context, wallet [20]byte, digest [32]byte, sig []byte) (bool, error)
}

// ErrAgentNotFound is returned by ChainClient when a token does not exist.
var ErrAgentNotFound = errors.New("agent not found")

// RegistrationFetcher retrieves and parses an agent registration file.
//
// Implementations MUST be SSRF-hardened: scheme allow-list, response size cap,
// timeout, redirect limit and private-range blocking (threat TH-8). The
// interface returns the parsed file so the verifier never sees raw bytes and
// cannot be tricked into parsing them a second, different way.
type RegistrationFetcher interface {
	Fetch(ctx context.Context, uri string) (*RegistrationFile, error)
}

// NonceStore records consumed nonces and commits bindings.
//
// Commit MUST be atomic: insert the nonce under a UNIQUE constraint and write
// the binding record in ONE transaction. See the B3/B15 split below.
type NonceStore interface {
	// Seen reports whether a nonce has already been consumed (check B3).
	Seen(ctx context.Context, nonce string) (bool, error)

	// Commit atomically consumes the nonce, revokes any prior active binding for
	// the same CAID, and inserts the new record (check B15). It MUST return
	// ErrNonceReused if the nonce was consumed concurrently.
	Commit(ctx context.Context, rec *Record) error

	// ActiveByWallet returns the CAID currently bound to a wallet, or "" if none
	// (check B9a).
	ActiveByWallet(ctx context.Context, wallet string) (string, error)
}

// ErrNonceReused is returned by NonceStore.Commit when the unique constraint on
// the nonce fires.
var ErrNonceReused = errors.New("nonce already consumed")

// Record is a committed binding.
type Record struct {
	ID              string
	CAID            string
	PeerID          string
	MeshID          string
	SidecarKey      string
	AgentWallet     string
	Owner           string
	Nonce           string
	Document        []byte
	PeerSignature   []byte
	WalletSignature []byte
	DomainVerified  bool
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

// TrustedRegistry is an allow-listed ERC-8004 deployment.
type TrustedRegistry struct {
	// Tuple is the canonical lowercase CAIP string.
	Tuple     string
	Namespace string
	ChainID   *big.Int
	Address   [20]byte
}

// Config parameterises verification.
type Config struct {
	MeshID       string
	ControlPlane string

	// MaxTTL bounds expiresAt - issuedAt (check B1). Without an upper bound a
	// signer could self-issue a decade-long binding, defeating AMB-5 and
	// outliving the nonce retention window, after which the document becomes
	// replayable.
	MaxTTL time.Duration

	// ClockSkew tolerated on issuedAt.
	ClockSkew time.Duration

	// TrustedRegistries is the B2a allow-list. MUST be non-empty; an empty
	// allow-list would mean "trust any registry", which is the TH-3a attack.
	TrustedRegistries []TrustedRegistry

	// RequireUniqueAgentWallet enables check B9a.
	RequireUniqueAgentWallet bool

	// Now is injectable for deterministic tests.
	Now func() time.Time
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// Verifier runs the B1..B15 pipeline.
type Verifier struct {
	cfg     Config
	chain   ChainClient
	fetcher RegistrationFetcher
	store   NonceStore
}

// NewVerifier constructs a Verifier, rejecting configurations that would be
// silently insecure.
func NewVerifier(cfg Config, chain ChainClient, fetcher RegistrationFetcher, store NonceStore) (*Verifier, error) {
	if cfg.MeshID == "" {
		return nil, fmt.Errorf("config: meshId is required")
	}
	if cfg.ControlPlane == "" {
		return nil, fmt.Errorf("config: controlPlane is required")
	}
	if len(cfg.TrustedRegistries) == 0 {
		// Failing loudly here is the point. An empty allow-list is not a
		// permissive default, it is the TH-3a vulnerability with extra steps.
		return nil, fmt.Errorf("config: at least one trusted registry is required; " +
			"an empty allow-list would accept an attacker-deployed registry (check B2a)")
	}
	if cfg.MaxTTL <= 0 {
		return nil, fmt.Errorf("config: maxTTL must be positive (check B1)")
	}
	return &Verifier{cfg: cfg, chain: chain, fetcher: fetcher, store: store}, nil
}

// Input is a binding submission.
type Input struct {
	Document        []byte
	PeerPublicKey   []byte
	PeerSignature   []byte
	WalletSignature []byte
}

// Result is a successful verification.
type Result struct {
	Record   *Record
	Registry TrustedRegistry
	// DomainVerified reports the OPTIONAL ERC-8004 endpoint-domain check (B14).
	// It never gates admission; it is surfaced as a trust signal.
	DomainVerified bool
}

// Verify runs checks B1 through B15 IN ORDER and denies on the first failure.
//
// The ordering is not cosmetic. Three places where it is load-bearing:
//
//   - B2a BEFORE B6. Every chain read and the EIP-712 domain must be derived
//     from an allow-listed registry. If the document's own agentRegistry were
//     trusted, an attacker could deploy an ERC-8004-shaped contract, mint
//     themselves agentId 42 with a wallet they control, and satisfy B6-B9
//     against their own registry (TH-3a).
//
//   - B3 CHECKS, B15 CONSUMES. Consuming the nonce before signature
//     verification would let an unauthenticated caller burn arbitrary nonces
//     (TH-17). Merely checking without an atomic insert would let two
//     concurrent submissions both pass B3 and both commit.
//
//   - B1's UPPER BOUND. Without expiresAt <= issuedAt + maxTTL a signer could
//     self-issue a binding that outlives nonce retention, after which the
//     document is replayable.
func (v *Verifier) Verify(ctx context.Context, in Input) (*Result, error) {
	doc, err := Parse(in.Document)
	if err != nil {
		return nil, &Error{Reason: ReasonMalformed, Detail: err.Error(), Err: err}
	}

	if err := v.checkFreshness(doc); err != nil { // B1
		return nil, err
	}
	if err := v.checkMesh(doc); err != nil { // B2
		return nil, err
	}
	reg, err := v.checkRegistry(doc) // B2a
	if err != nil {
		return nil, err
	}
	if err := v.checkNonceUnseen(ctx, doc); err != nil { // B3
		return nil, err
	}
	if err := VerifyPeerProof(doc, in.PeerPublicKey, in.PeerSignature); err != nil { // B4, B5
		return nil, err
	}

	owner, wallet, err := v.checkOnChainIdentity(ctx, doc, reg) // B6, B7, B8
	if err != nil {
		return nil, err
	}
	if err := v.verifyWalletProof(ctx, doc, reg, wallet, in.WalletSignature); err != nil { // B9
		return nil, err
	}
	if err := v.checkWalletUniqueness(ctx, doc); err != nil { // B9a
		return nil, err
	}

	domainVerified, err := v.checkRegistrationFile(ctx, doc, reg) // B10..B14
	if err != nil {
		return nil, err
	}

	// B15: atomic commit.
	issuedAt, _ := doc.IssuedAtTime()
	expiresAt, _ := doc.ExpiresAtTime()
	rec := &Record{
		ID:              newRecordID(),
		CAID:            doc.CAID(),
		PeerID:          doc.PeerID,
		MeshID:          doc.MeshID,
		SidecarKey:      doc.SidecarKey,
		AgentWallet:     doc.AgentWallet,
		Owner:           FormatAddress(owner),
		Nonce:           doc.Nonce,
		Document:        in.Document,
		PeerSignature:   in.PeerSignature,
		WalletSignature: in.WalletSignature,
		DomainVerified:  domainVerified,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
	}
	if err := v.store.Commit(ctx, rec); err != nil {
		if errors.Is(err, ErrNonceReused) {
			return nil, denyf(ReasonNonceReused, "B15",
				"nonce was consumed concurrently by another submission")
		}
		return nil, denyf(ReasonCommitFailed, "B15", "%v", err)
	}

	return &Result{Record: rec, Registry: reg, DomainVerified: domainVerified}, nil
}

// checkFreshness implements B1.
func (v *Verifier) checkFreshness(doc *Document) error {
	issuedAt, err := doc.IssuedAtTime()
	if err != nil {
		return denyf(ReasonBadTimestamp, "B1", "%v", err)
	}
	expiresAt, err := doc.ExpiresAtTime()
	if err != nil {
		return denyf(ReasonBadTimestamp, "B1", "%v", err)
	}
	if !issuedAt.Before(expiresAt) {
		return denyf(ReasonBadTimestamp, "B1", "issuedAt %s is not before expiresAt %s",
			doc.IssuedAt, doc.ExpiresAt)
	}
	if ttl := expiresAt.Sub(issuedAt); ttl > v.cfg.MaxTTL {
		return denyf(ReasonTTLTooLong, "B1",
			"lifetime %s exceeds the maximum %s; a self-issued long-lived binding "+
				"would outlive nonce retention and become replayable", ttl, v.cfg.MaxTTL)
	}
	now := v.cfg.now()
	if now.Before(issuedAt.Add(-v.cfg.ClockSkew)) {
		return denyf(ReasonNotYetValid, "B1", "issuedAt %s is in the future", doc.IssuedAt)
	}
	if !now.Before(expiresAt) {
		return denyf(ReasonExpired, "B1", "expired at %s", doc.ExpiresAt)
	}
	return nil
}

// checkMesh implements B2.
func (v *Verifier) checkMesh(doc *Document) error {
	if doc.MeshID != v.cfg.MeshID {
		return denyf(ReasonWrongMesh, "B2", "document is for mesh %q, this broker serves %q",
			doc.MeshID, v.cfg.MeshID)
	}
	if doc.ControlPlane != v.cfg.ControlPlane {
		return denyf(ReasonWrongControlPlane, "B2",
			"document names control plane %q, this broker is %q",
			doc.ControlPlane, v.cfg.ControlPlane)
	}
	return nil
}

// checkRegistry implements B2a: the registry tuple MUST be allow-listed, and
// everything downstream derives from the MATCHED entry, never from the document.
func (v *Verifier) checkRegistry(doc *Document) (TrustedRegistry, error) {
	for _, r := range v.cfg.TrustedRegistries {
		if r.Tuple == doc.AgentRegistry {
			return r, nil
		}
	}
	return TrustedRegistry{}, denyf(ReasonRegistryNotAllowed, "B2a",
		"registry %q is not allow-listed; an attacker-deployed ERC-8004-shaped "+
			"registry would otherwise satisfy every subsequent check", doc.AgentRegistry)
}

// checkNonceUnseen implements B3. It only CHECKS; consumption happens at B15.
func (v *Verifier) checkNonceUnseen(ctx context.Context, doc *Document) error {
	seen, err := v.store.Seen(ctx, doc.Nonce)
	if err != nil {
		return denyf(ReasonCommitFailed, "B3", "nonce lookup failed: %v", err)
	}
	if seen {
		return denyf(ReasonNonceReused, "B3", "nonce has already been consumed")
	}
	return nil
}

// checkOnChainIdentity implements B6, B7 and B8.
func (v *Verifier) checkOnChainIdentity(ctx context.Context, doc *Document, reg TrustedRegistry) (owner, wallet [20]byte, err error) {
	agentID, cerr := doc.AgentIDInt()
	if cerr != nil {
		return owner, wallet, denyf(ReasonMalformed, "B6", "%v", cerr)
	}

	owner, cerr = v.chain.OwnerOf(ctx, reg.Address, agentID)
	if cerr != nil {
		if errors.Is(cerr, ErrAgentNotFound) {
			return owner, wallet, denyf(ReasonAgentNotFound, "B6",
				"agent %s does not exist in registry %s", doc.AgentID, reg.Tuple)
		}
		return owner, wallet, denyf(ReasonChainUnavailable, "B6", "ownerOf failed: %v", cerr)
	}

	wallet, cerr = v.chain.GetAgentWallet(ctx, reg.Address, agentID)
	if cerr != nil {
		return owner, wallet, denyf(ReasonChainUnavailable, "B7", "getAgentWallet failed: %v", cerr)
	}
	if wallet == ([20]byte{}) {
		// ERC-8004 clears agentWallet on ERC-721 transfer, so this is the normal
		// state of a freshly-sold agent, not an error condition.
		return owner, wallet, denyf(ReasonWalletUnset, "B7",
			"agentWallet is unset; it is cleared automatically when the agent NFT is "+
				"transferred and must be re-verified by the new owner")
	}

	claimed, cerr := ParseAddress(doc.AgentWallet)
	if cerr != nil {
		return owner, wallet, denyf(ReasonMalformed, "B8", "%v", cerr)
	}
	if claimed != wallet {
		return owner, wallet, denyf(ReasonWalletMismatch, "B8",
			"document claims agentWallet %s but the registry reports %s",
			doc.AgentWallet, FormatAddress(wallet))
	}
	return owner, wallet, nil
}

// verifyWalletProof implements B9, dispatching between EOA and ERC-1271.
func (v *Verifier) verifyWalletProof(ctx context.Context, doc *Document, reg TrustedRegistry, wallet [20]byte, sig []byte) error {
	// The domain comes from the ALLOW-LISTED tuple. This is the second half of
	// the B2a defence: even a correctly-signed document is verified against the
	// domain WE chose, not one the submitter chose.
	domain := DomainParams{ChainID: reg.ChainID, VerifyingContract: reg.Address}

	err := VerifyWalletProof(doc, domain, wallet, sig)
	if err == nil {
		return nil
	}

	// EOA recovery failed. The wallet may be a contract (Safe, EIP-7702), so try
	// ERC-1271 before denying -- ERC-8004 itself supports both.
	digest, derr := MeshBindingDigest(doc, domain)
	if derr != nil {
		return denyf(ReasonMalformed, "B9", "compute digest: %v", derr)
	}
	ok, cerr := v.chain.IsValidERC1271Signature(ctx, wallet, digest, sig)
	if cerr != nil {
		// Report the ORIGINAL EOA failure: for the overwhelmingly common case of
		// a plain EOA with a bad signature, an ERC-1271 RPC error is a confusing
		// thing to surface.
		return err
	}
	if !ok {
		return denyf(ReasonWalletSignatureInvalid, "B9",
			"signature is not valid as an EOA signature nor via ERC-1271")
	}
	return nil
}

// checkWalletUniqueness implements B9a.
func (v *Verifier) checkWalletUniqueness(ctx context.Context, doc *Document) error {
	if !v.cfg.RequireUniqueAgentWallet {
		return nil
	}
	existing, err := v.store.ActiveByWallet(ctx, doc.AgentWallet)
	if err != nil {
		return denyf(ReasonCommitFailed, "B9a", "wallet lookup failed: %v", err)
	}
	if existing != "" && existing != doc.CAID() {
		return denyf(ReasonWalletBoundElsewhere, "B9a",
			"wallet %s is already bound to %s; two agents sharing a wallet would "+
				"silently share ERC-8226 mandates and caps", doc.AgentWallet, existing)
	}
	return nil
}

// checkRegistrationFile implements B10 through B14.
func (v *Verifier) checkRegistrationFile(ctx context.Context, doc *Document, reg TrustedRegistry) (bool, error) {
	agentID, err := doc.AgentIDInt()
	if err != nil {
		return false, denyf(ReasonMalformed, "B10", "%v", err)
	}
	uri, cerr := v.chain.AgentURI(ctx, reg.Address, agentID)
	if cerr != nil {
		return false, denyf(ReasonChainUnavailable, "B10", "agentURI failed: %v", cerr)
	}

	file, ferr := v.fetcher.Fetch(ctx, uri)
	if ferr != nil {
		return false, denyf(ReasonRegistrationUnreachable, "B10",
			"could not fetch registration file %q: %v", uri, ferr)
	}

	// B11: the file must point back at THIS registry and agent id, which is what
	// stops one agent's file being reused to vouch for another.
	if !file.HasRegistration(reg.Tuple, doc.AgentID) {
		return false, denyf(ReasonRegistrationMismatch, "B11",
			"registration file does not contain a registrations entry for %s/%s",
			reg.Tuple, doc.AgentID)
	}

	// B12: the file must advertise THIS PeerID on THIS mesh. Removing this
	// advertisement is a supported revocation path (threat TH-16).
	if !file.AdvertisesSAM(doc.PeerID, doc.MeshID) {
		return false, denyf(ReasonSAMEndpointMissing, "B12",
			"registration file has no SAM service entry advertising sam://%s@%s",
			doc.PeerID, doc.MeshID)
	}

	// B13.
	if !file.Active {
		return false, denyf(ReasonAgentInactive, "B13", "registration file marks the agent inactive")
	}

	// B14 is OPTIONAL and never gates admission.
	return file.DomainVerified, nil
}
