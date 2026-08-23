// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IAgentMandate} from "./IAgentMandate.sol";
import {IComplianceProvider} from "./IComplianceProvider.sol";

/// @title ISatmAgentMandate
/// @notice SATM's additions on top of ERC-8226. Every member here is an EXTENSION,
///         not part of the standard. They are isolated in this interface so that
///         conformance tests can assert against {IAgentMandate} alone and a future
///         revision of the draft EIP does not entangle with SATM's own rules.
///
/// @dev Each addition strictly NARROWS what is accepted; none widens it. Rationale
///      lives in SPECIFICATION.md 7.2 (rules 11-13), 7.2a, 7.2b and 7.3.1.
interface ISatmAgentMandate is IAgentMandate {
    /// @notice A wallet's immutably-pinned ERC-8004 agent identity.
    /// @dev Write-once. Immutability is load-bearing: if the pin were re-settable,
    ///      a wallet whose agent NFT was transferred could simply re-point itself at
    ///      a freshly registered agentId and reuse its stale mandate (threat TH-5c).
    struct AgentIdentity {
        address identityRegistry;
        uint256 agentId;
        bool set;
    }

    /// @notice Emitted once per wallet, when its agent identity is pinned.
    event AgentIdentityDeclared(
        address indexed agent, address indexed identityRegistry, uint256 indexed agentId
    );

    /// @notice Emitted when the governance allow-list of compliance providers changes.
    event ComplianceProviderAllowed(address indexed provider, bool allowed);

    /// @notice Emitted when the allow-list of ERC-8004 identity registries changes.
    event IdentityRegistryAllowed(address indexed identityRegistry, bool allowed);

    // ---------------------------------------------------------------------
    // Rule 13 / 7.2b - on-chain agent identity pinning
    // ---------------------------------------------------------------------

    /// @notice Pins the calling wallet to exactly one `(identityRegistry, agentId)`.
    /// @dev MUST revert if the registry is not allow-listed, if this wallet has already
    ///      declared an identity, or if the caller is not the current `agentWallet` of
    ///      `agentId`. There is deliberately NO un-declare and NO re-declare.
    function declareAgentIdentity(address identityRegistry, uint256 agentId) external;

    /// @notice Returns the pinned identity for an agent wallet.
    function agentIdentity(address agent) external view returns (AgentIdentity memory);

    /// @notice True only if the pinned identity STILL resolves to this wallet on-chain.
    /// @dev False once the agent's ERC-721 token is transferred, because ERC-8004 clears
    ///      `agentWallet` on transfer. This is what makes a sold agent's mandates inert.
    function isAgentIdentityLive(address agent) external view returns (bool);

    // ---------------------------------------------------------------------
    // Rule 11 - compliance provider allow-list
    // ---------------------------------------------------------------------

    /// @notice True if `provider` is on the governance-managed allow-list.
    /// @dev ERC-8226 requires only that `complianceProvider != address(0)`, which would
    ///      let a principal nominate an always-eligible provider under their own control
    ///      and thereby self-certify.
    function isAllowedProvider(address provider) external view returns (bool);

    /// @notice True if `identityRegistry` is on the governance-managed allow-list.
    function isAllowedIdentityRegistry(address identityRegistry) external view returns (bool);

    // ---------------------------------------------------------------------
    // Rule 12 - views the RAMS-aware asset needs
    // ---------------------------------------------------------------------

    /// @notice Returns the full mandate struct for a pair.
    /// @dev The asset needs `complianceProvider` and `identityRef` to re-check principal
    ///      eligibility at execution time (SPECIFICATION.md 7.3.1 step 2a), which the
    ///      standard's own surface does not expose.
    function getMandate(address agent, address principal) external view returns (Mandate memory);

    /// @notice `canExecute` plus SATM's agent-identity liveness check.
    /// @dev {IAgentMandate-canExecute} is left byte-for-byte conformant with the EIP and
    ///      therefore does NOT include the liveness check. Callers that want SATM's
    ///      stricter semantics use this. `recordExecution` enforces liveness regardless,
    ///      so an asset that only ever calls the conformant view is still protected.
    function canExecuteStrict(address agent, address principal, address asset, bytes32 action, uint256 amount)
        external
        view
        returns (bool);

    /// @notice Decodes why an authorization would fail, for operator diagnostics.
    /// @dev `canExecute` returns a bare boolean, which is useless for explaining a denial
    ///      to a human. Mirrors the reason codes the sidecar surfaces (SPECIFICATION.md 6.3.5).
    function explainExecution(address agent, address principal, address asset, bytes32 action, uint256 amount)
        external
        view
        returns (bool allowed, DenialReason reason);

    enum DenialReason {
        NONE, // 0 - allowed
        NO_MANDATE, // 1 - mandate does not exist
        WRONG_ASSET, // 2 - asset != mandate.asset
        OUTSIDE_WINDOW, // 3 - before validFrom or after validUntil
        REVOKED, // 4 - mandate revoked
        ACTION_DISABLED, // 5 - action not enabled on this mandate
        FROZEN, // 6 - agent frozen by an enforcer
        PER_TX_CAP, // 7 - amount > maxTransactionValue
        CUMULATIVE_CAP, // 8 - cumulativeUsed + amount > maxCumulativeValue
        IDENTITY_NOT_LIVE // 9 - SATM: pinned agent identity no longer resolves
    }
}
