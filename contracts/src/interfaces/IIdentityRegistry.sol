// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IIdentityRegistry
/// @notice The subset of the ERC-8004 Identity Registry that SATM contracts depend on.
///
/// @dev Signatures verified against the vendored implementation at
///      vendor/erc8004/IdentityRegistryUpgradeable.sol (pinned commit b9e466c).
///      This is intentionally a narrow view rather than a full transcription: SATM
///      only ever READS identity state on-chain, and a narrow interface makes that
///      constraint enforceable at compile time.
interface IIdentityRegistry {
    /// @notice The address at which the agent receives payments.
    /// @dev ERC-8004 reserves this metadata key and CLEARS it automatically when the
    ///      agent's ERC-721 token is transferred. That behaviour is load-bearing for
    ///      SATM: it is what makes a sold agent's mandates and payouts inert without
    ///      any SATM-specific bookkeeping. See SPECIFICATION.md 7.3.2.
    function getAgentWallet(uint256 agentId) external view returns (address);

    /// @notice ERC-721 owner of the agent.
    function ownerOf(uint256 agentId) external view returns (address);

    /// @notice Resolves to the agent's registration file.
    function tokenURI(uint256 agentId) external view returns (string memory);

    /// @notice Optional on-chain metadata.
    function getMetadata(uint256 agentId, string memory metadataKey) external view returns (bytes memory);

    /// @notice True if `spender` is the owner of, or approved for, `agentId`.
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
}
