// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IAgentMandate
/// @notice Verbatim transcription of the `IAgentMandate` interface from ERC-8226
///         (Regulated Agent Mandate), https://eips.ethereum.org/EIPS/eip-8226.
///
/// @dev DO NOT add SATM-specific members to this file. See {IComplianceProvider}
///      for the rationale. SATM's additions live in {ISatmAgentMandate}.
///
///      Key normative properties this interface encodes, each of which has a
///      corresponding conformance test (see test/conformance):
///
///       - Mandate storage is keyed by `(agent, principal)`, and each pair has at
///         most one active mandate at any given time.
///       - A mandate authorises actions against exactly ONE `asset`.
///       - `type(uint256).max` in a cap means "no limit".
///       - Caps are denominated in the asset's transfer QUANTITY, not in fiat.
///       - `cumulativeUsed` MUST NOT reset on `extendMandate`.
interface IAgentMandate is IERC165 {
    struct Mandate {
        address agent;
        uint48 validFrom;
        uint48 validUntil;
        address principal;
        bool revoked;
        address complianceProvider;
        bytes32 identityRef;
        address asset;
        uint256 maxTransactionValue;
        uint256 maxCumulativeValue;
        uint256 cumulativeUsed;
        bytes32 metadata;
    }

    /// @notice Parameters for grantMandate, bundled into a struct to avoid stack-too-deep.
    struct GrantMandateParams {
        address agent;
        uint48 validFrom;
        uint48 validUntil;
        address principal;
        address complianceProvider;
        bytes32 identityRef;
        address asset;
        uint256 maxTransactionValue;
        uint256 maxCumulativeValue;
        bytes32 metadata;
        bytes32[] actions;
        uint256 deadline;
    }

    /// @notice Emitted when a mandate is granted.
    event MandateGranted(
        address indexed agent,
        address indexed principal,
        address complianceProvider,
        address asset,
        uint48 validFrom,
        uint48 validUntil,
        bytes32 metadata
    );

    /// @notice Emitted when an action is enabled on a mandate at grant time.
    event ActionEnabled(address indexed agent, address indexed principal, bytes32 indexed action);

    /// @notice Emitted when a mandate is revoked.
    event MandateRevoked(address indexed agent, address indexed principal, address revokedBy);

    /// @notice Emitted when a mandate's validity is extended.
    event MandateExtended(address indexed agent, address indexed principal, uint48 newValidUntil);

    /// @notice Emitted when an operator approval is set or revoked.
    event OperatorSet(address indexed principal, address indexed operator, bool approved);

    /// @notice Emitted when an agent executes an action recorded by a RAMS-aware token.
    event ExecutionRecorded(
        address indexed agent,
        address indexed principal,
        bytes32 indexed action,
        uint256 amount,
        uint256 cumulativeUsed
    );

    /// @notice Emitted when an agent is frozen. Freezing is restricted to authorized enforcer roles.
    event AgentFrozen(address indexed agent, address indexed enforcer);

    /// @notice Emitted when a freeze is lifted.
    event AgentUnfrozen(address indexed agent, address indexed enforcer);

    /// @notice Grants a mandate from a principal to an agent.
    /// @dev If `signature` is empty, msg.sender MUST equal params.principal. Otherwise the
    ///      signature is verified via SignatureChecker against the GrantMandate EIP-712 digest.
    function grantMandate(GrantMandateParams calldata params, bytes calldata signature) external;

    /// @notice Revokes the active mandate for the given agent and principal.
    function revokeMandate(address agent, address principal, uint256 deadline, bytes calldata signature)
        external;

    /// @notice Extends the validity of an existing mandate without resetting cumulativeUsed.
    function extendMandate(
        address agent,
        address principal,
        uint48 newValidUntil,
        uint256 deadline,
        bytes calldata signature
    ) external;

    /// @notice Freezes an agent, halting all of its mandates. Restricted to authorized enforcer roles.
    function freezeAgent(address agent) external;

    /// @notice Lifts a freeze on an agent.
    function unfreezeAgent(address agent) external;

    /// @notice Sets or revokes operator approval for the principal.
    function setOperator(
        address principal,
        address operator,
        bool approved,
        uint256 deadline,
        bytes calldata signature
    ) external;

    /// @notice Records an agent-initiated execution. Called by RAMS-aware regulated tokens.
    function recordExecution(address agent, address principal, bytes32 action, uint256 amount) external;

    /// @notice Returns true if the agent can execute the action on the asset for the principal.
    function canExecute(address agent, address principal, address asset, bytes32 action, uint256 amount)
        external
        view
        returns (bool);

    /// @notice Returns true if the action is enabled on the mandate.
    function isActionEnabled(address agent, address principal, bytes32 action) external view returns (bool);

    /// @notice Returns true if the agent is frozen.
    function isFrozen(address agent) external view returns (bool);
}
