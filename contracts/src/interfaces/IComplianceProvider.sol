// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IComplianceProvider
/// @notice Verbatim transcription of the `IComplianceProvider` interface from ERC-8226
///         (Regulated Agent Mandate), https://eips.ethereum.org/EIPS/eip-8226.
///
/// @dev DO NOT add SATM-specific members to this file. It is a transcription of a
///      Draft EIP and is kept byte-faithful so that (a) conformance tests assert
///      against the standard as written, and (b) a future revision of the draft
///      produces a reviewable diff confined to this file. SATM's own additions live
///      in {ISatmAgentMandate}.
///
///      ERC-8226 specification text is CC0. This file carries the repository's
///      Apache-2.0 header for consistency; the interface itself is not claimed.
interface IComplianceProvider is IERC165 {
    enum ReasonCode {
        COMPLIANT, // 0
        KYC_EXPIRED, // 1
        AML_FLAG, // 2
        NOT_ACCREDITED, // 3
        NOT_QUALIFIED, // 4
        JURISDICTION_BLOCKED, // 5
        IDENTITY_NOT_FOUND, // 6
        ATTESTATION_REVOKED, // 7
        OTHER // 8
    }

    /// @notice Emitted when a principal is granted eligibility.
    event PrincipalGranted(address indexed principal, bytes32 indexed identityRef);

    /// @notice Emitted when a previously eligible principal is revoked.
    event PrincipalRevoked(address indexed principal, bytes32 indexed identityRef, ReasonCode reason);

    /// @notice Grants eligibility to a principal.
    /// @param principal The on-chain address of the principal.
    /// @param identityRef An off-chain identity reference (e.g., keccak256 of a
    ///        Decentralized Identifier (DID) or attestation ID).
    /// @param expiresAt Unix timestamp after which eligibility MUST be re-checked.
    ///        0 means no expiry.
    function grantPrincipal(address principal, bytes32 identityRef, uint48 expiresAt) external;

    /// @notice Revokes a principal's eligibility.
    /// @param principal The on-chain address of the principal.
    /// @param reason The reason for revocation.
    function revokePrincipal(address principal, ReasonCode reason) external;

    /// @notice Returns eligibility of a principal.
    /// @dev MUST return structured data sufficient for regulatory audit: a binary
    ///      oracle is non-conformant, since reason codes and expiry timestamps are
    ///      required for any credible compliance trail. MUST verify that
    ///      `identityRef` resolves to a valid, unrevoked attestation and return
    ///      `eligible == false` if it does not.
    /// @param principal The on-chain address of the principal.
    /// @param identityRef An off-chain identity reference.
    /// @return eligible True if the principal is compliant.
    /// @return reason Reason code. MUST be COMPLIANT when eligible is true.
    /// @return expiresAt Unix timestamp after which this result MUST be re-checked.
    ///         0 means no expiry.
    function checkPrincipal(address principal, bytes32 identityRef)
        external
        view
        returns (bool eligible, ReasonCode reason, uint48 expiresAt);
}
