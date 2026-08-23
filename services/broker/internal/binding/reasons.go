package binding

import (
	"errors"
	"fmt"
)

// Reason is a stable, machine-readable code explaining why a binding was
// rejected.
//
// These are part of the broker's API contract (SPECIFICATION.md 6.1.4) and are
// written into the evidence log, so they must not be reworded casually: an
// operator diagnosing a denial, and an auditor reading an anchored evidence
// batch months later, both key off these strings.
//
// Codes map one-to-one onto the checks in SPECIFICATION.md 4.6, which is what
// makes "one test per check, each proving denial in isolation" a mechanical
// exercise rather than a judgement call.
type Reason string

const (
	// ReasonOK is the absence of a denial.
	ReasonOK Reason = "ok"

	// Structural, before any check runs.
	ReasonMalformed Reason = "binding.malformed"

	// B1 - freshness and bounded lifetime.
	ReasonNotYetValid  Reason = "binding.not_yet_valid"
	ReasonExpired      Reason = "binding.expired"
	ReasonTTLTooLong   Reason = "binding.ttl_too_long"
	ReasonBadTimestamp Reason = "binding.bad_timestamp"

	// B2 - mesh binding.
	ReasonWrongMesh         Reason = "binding.wrong_mesh"
	ReasonWrongControlPlane Reason = "binding.wrong_control_plane"

	// B2a - registry allow-list. See threat TH-3a: without this, an attacker
	// deploys their own ERC-8004-shaped registry, mints themselves any agentId
	// with any agentWallet, and produces a binding where every other check
	// passes.
	ReasonRegistryNotAllowed Reason = "binding.registry_not_allowed"

	// B3 / B15 - nonce.
	ReasonNonceReused Reason = "binding.nonce_reused"

	// B4, B5 - PeerID proof.
	ReasonPeerKeyMismatch      Reason = "binding.peer_key_mismatch"
	ReasonPeerSignatureInvalid Reason = "binding.peer_signature_invalid"

	// B6, B7, B8 - on-chain identity.
	ReasonAgentNotFound    Reason = "binding.agent_not_found"
	ReasonWalletUnset      Reason = "binding.agent_wallet_unset"
	ReasonWalletMismatch   Reason = "binding.agent_wallet_mismatch"
	ReasonChainUnavailable Reason = "binding.chain_unavailable"

	// B9 - wallet proof.
	ReasonWalletSignatureInvalid Reason = "binding.wallet_signature_invalid"

	// B9a - one wallet backs at most one agent. Without this, two agents sharing
	// an agentWallet would silently share ERC-8226 mandates and caps, because
	// RAMS keys mandates by (agent, principal). See SPECIFICATION.md 7.2a.
	ReasonWalletBoundElsewhere Reason = "binding.wallet_bound_elsewhere"

	// B10..B13 - registration file.
	ReasonRegistrationUnreachable Reason = "binding.registration_unreachable"
	ReasonRegistrationMalformed   Reason = "binding.registration_malformed"
	ReasonRegistrationMismatch    Reason = "binding.registration_mismatch"
	ReasonSAMEndpointMissing      Reason = "binding.sam_endpoint_missing"
	ReasonAgentInactive           Reason = "binding.agent_inactive"

	// B15 - commit.
	ReasonCommitFailed Reason = "binding.commit_failed"
)

// Error is a denial carrying both a stable Reason and a human-readable detail.
//
// The split matters: the Reason is what policy, metrics and evidence key off,
// while the detail is what a human needs in order to fix the problem. Collapsing
// them into one string makes the first unstable and the second unsearchable.
type Error struct {
	Reason Reason
	// Check names the specification check that failed ("B2a", "B9"), or is empty
	// for structural failures. Present so an operator can go straight to the
	// relevant part of SPECIFICATION.md 4.6.
	Check  string
	Detail string
	Err    error
}

func (e *Error) Error() string {
	prefix := string(e.Reason)
	if e.Check != "" {
		prefix = fmt.Sprintf("%s (%s)", e.Reason, e.Check)
	}
	if e.Detail == "" {
		return prefix
	}
	return fmt.Sprintf("%s: %s", prefix, e.Detail)
}

func (e *Error) Unwrap() error { return e.Err }

// denyf builds a denial for a named check.
func denyf(reason Reason, check, format string, args ...any) *Error {
	return &Error{Reason: reason, Check: check, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf extracts the Reason from an error, or ReasonMalformed if the error
// did not come from binding verification.
func ReasonOf(err error) Reason {
	if err == nil {
		return ReasonOK
	}
	var be *Error
	if errors.As(err, &be) {
		return be.Reason
	}
	return ReasonMalformed
}
