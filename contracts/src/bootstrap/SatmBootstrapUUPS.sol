// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @title SatmBootstrapUUPS
/// @notice Bootstrap implementation used to stand a UUPS proxy up with a known owner
///         before upgrading it to a real ERC-8004 registry implementation.
///
/// @dev Why this exists.
///
///      The vendored registries deliberately do NOT call `__Ownable_init` in their own
///      `initialize()`; that function is `reinitializer(2) onlyOwner`, so an owner must
///      already exist before it can be called. Upstream solves this with
///      `vendor/erc8004/MinimalUUPS.sol`, which hard-codes the owner to a single
///      address for their vanity-address deployment scheme.
///
///      A hard-coded owner is unusable on a local devnet or in CI, where the deployer is
///      an ephemeral anvil account. This contract is equivalent in storage layout but
///      takes the owner as a parameter.
///
///      Storage layout MUST match the registries: `_identityRegistry` occupies slot 0,
///      outside the ERC-7201 namespaced storage the registries use for everything else.
///      Reordering or adding state here would corrupt the proxy after upgrade.
///
///      This lives in src/, not vendor/, because it is SATM-authored. vendor/ stays a
///      pristine copy of upstream.
contract SatmBootstrapUUPS is OwnableUpgradeable, UUPSUpgradeable {
    /// @dev Slot 0. Mirrors `_identityRegistry` in the Reputation and Validation registries.
    address private _identityRegistry;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param owner_ The address that will own the proxy and may authorize upgrades.
    /// @param identityRegistry_ Seed value for slot 0. Pass address(0) for the Identity
    ///        Registry itself, which does not use this slot.
    function initialize(address owner_, address identityRegistry_) public initializer {
        __Ownable_init(owner_);
        __UUPSUpgradeable_init();
        _identityRegistry = identityRegistry_;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function getVersion() external pure returns (string memory) {
        return "satm-bootstrap-0.1.0";
    }
}
