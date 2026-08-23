// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {SatmBootstrapUUPS} from "../bootstrap/SatmBootstrapUUPS.sol";
import {IdentityRegistryUpgradeable} from "erc8004/IdentityRegistryUpgradeable.sol";
import {ReputationRegistryUpgradeable} from "erc8004/ReputationRegistryUpgradeable.sol";
import {ValidationRegistryUpgradeable} from "erc8004/ValidationRegistryUpgradeable.sol";

/// @title Erc8004Deployer
/// @notice Deploys the three ERC-8004 registries behind UUPS proxies.
///
/// @dev Shared by the Foundry deploy script and the integration tests so both exercise
///      the SAME deployment path. A test that stands the registries up differently from
///      production is testing a fiction.
///
///      The dance is dictated by upstream, not by choice:
///
///        1. Deploy a bootstrap implementation and put a proxy in front of it. The
///           bootstrap's `initialize` is what calls `__Ownable_init`, giving the proxy
///           an owner.
///        2. Upgrade the proxy to the real registry implementation.
///        3. Call the registry's own `initialize`, which is `reinitializer(2) onlyOwner`
///           and therefore requires step 1 to have happened.
///
///      Every call in steps 2 and 3 must come from `owner`.
library Erc8004Deployer {
    struct Deployment {
        address identityRegistry;
        address reputationRegistry;
        address validationRegistry;
    }

    /// @notice Deploys a single UUPS proxy, owned by `owner`, running `implementation`.
    /// @dev The caller MUST be `owner`, since the upgrade is `onlyOwner`.
    function _deployProxy(address owner, address implementation, address identityRegistrySeed)
        private
        returns (address proxy)
    {
        SatmBootstrapUUPS bootstrap = new SatmBootstrapUUPS();
        proxy = address(
            new ERC1967Proxy(
                address(bootstrap),
                abi.encodeCall(SatmBootstrapUUPS.initialize, (owner, identityRegistrySeed))
            )
        );
        UUPSUpgradeable(proxy).upgradeToAndCall(implementation, "");
    }

    /// @notice Deploys and initializes all three registries.
    /// @param owner Address that will own every proxy. MUST be the caller.
    function deployAll(address owner) internal returns (Deployment memory d) {
        // --- Identity -------------------------------------------------------
        // Does not use slot 0, so the seed is address(0).
        address identityImpl = address(new IdentityRegistryUpgradeable());
        d.identityRegistry = _deployProxy(owner, identityImpl, address(0));
        IdentityRegistryUpgradeable(d.identityRegistry).initialize();

        // --- Reputation -----------------------------------------------------
        address reputationImpl = address(new ReputationRegistryUpgradeable());
        d.reputationRegistry = _deployProxy(owner, reputationImpl, d.identityRegistry);
        ReputationRegistryUpgradeable(d.reputationRegistry).initialize(d.identityRegistry);

        // --- Validation -----------------------------------------------------
        // NOTE: no canonical deployment of this registry exists upstream, and the
        // ERC-8004 authors flag the validation section as still in flux. SATM deploys
        // its own and isolates use of it behind a port. See ADR-0004.
        address validationImpl = address(new ValidationRegistryUpgradeable());
        d.validationRegistry = _deployProxy(owner, validationImpl, d.identityRegistry);
        ValidationRegistryUpgradeable(d.validationRegistry).initialize(d.identityRegistry);
    }
}
