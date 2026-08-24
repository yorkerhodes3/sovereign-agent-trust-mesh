package attest

import "errors"

// Reason is a stable, machine-readable denial code.
//
// These are safe to return to a caller: they name WHICH check failed, which an
// honest client needs in order to correct itself, without disclosing the
// responder's own binding state, the broker's view of other agents, or anything
// else the caller has not already proven a right to see.
type Reason string

const (
	ReasonOK        Reason = "ok"
	ReasonMalformed Reason = "attestation.malformed"

	// V1
	ReasonWrongMesh         Reason = "attestation.wrong_mesh"
	ReasonWrongControlPlane Reason = "attestation.wrong_control_plane"

	// V2
	ReasonWrongTarget Reason = "attestation.wrong_target"

	// V3
	ReasonWrongService Reason = "attestation.wrong_service"
	ReasonWrongTool    Reason = "attestation.wrong_tool"

	// V4
	ReasonArgsMismatch Reason = "attestation.args_mismatch"

	// V5
	ReasonUnknownCallerBinding Reason = "attestation.unknown_caller_binding"
	ReasonBadSignature         Reason = "attestation.bad_signature"

	// V6
	ReasonBindingSuperseded  Reason = "attestation.binding_superseded"
	ReasonBindingRevoked     Reason = "attestation.binding_revoked"
	ReasonCallerPeerMismatch Reason = "attestation.caller_peer_mismatch"

	// V7
	ReasonExpired      Reason = "attestation.expired"
	ReasonNotYetValid  Reason = "attestation.not_yet_valid"
	ReasonTTLTooLong   Reason = "attestation.ttl_too_long"
	ReasonBadTimestamp Reason = "attestation.bad_timestamp"

	// V8
	ReasonNonceReused Reason = "attestation.nonce_reused"

	// Infrastructure, not a verdict on the attestation.
	ReasonTrustAPIUnavailable Reason = "attestation.trust_api_unavailable"
)

// Error carries a denial reason alongside the underlying cause.
type Error struct {
	Reason Reason
	Check  string
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Detail
}

func (e *Error) Unwrap() error { return e.Err }

func denied(reason Reason, check, detail string) *Error {
	return &Error{Reason: reason, Check: check, Detail: detail}
}

// ReasonOf extracts the reason from an error, or "" if it is not a denial.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
