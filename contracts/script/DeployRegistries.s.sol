// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Erc8004Deployer} from "satm/bootstrap/Erc8004Deployer.sol";

/// @title DeployRegistries
/// @notice Deploys the three ERC-8004 registries to a local devnet.
///
/// @dev Usage:
///
///   anvil --port 8545 &
///   forge script script/DeployRegistries.s.sol \
///     --rpc-url http://127.0.0.1:8545 --broadcast --private-key $PK
///
/// On PUBLIC testnets this script should NOT be used for Identity and Reputation:
/// canonical singletons already exist at deterministic addresses and SATM must use
/// them so it interoperates with the real ERC-8004 ecosystem rather than a private
/// fork of it (see docs/adr/0004-foundry-with-vendored-registries.md):
///
///   IdentityRegistry    0x8004A818BFB912233c491871b3d84c89A494BD9e   (testnets)
///   ReputationRegistry  0x8004B663056A597Dffe9eCcC1965A193B7388713   (testnets)
///
/// The Validation Registry has NO canonical deployment and its section of the ERC is
/// still being revised with the TEE community, so SATM deploys its own everywhere.
contract DeployRegistries is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);

        vm.startBroadcast(pk);
        Erc8004Deployer.Deployment memory d = Erc8004Deployer.deployAll(deployer);
        vm.stopBroadcast();

        console2.log("");
        console2.log("=== ERC-8004 registries deployed ===");
        console2.log("chainId            ", block.chainid);
        console2.log("deployer/owner     ", deployer);
        console2.log("IdentityRegistry   ", d.identityRegistry);
        console2.log("ReputationRegistry ", d.reputationRegistry);
        console2.log("ValidationRegistry ", d.validationRegistry);
        console2.log("");

        _writeDeploymentFile(d, deployer);
    }

    /// @dev Emits a JSON file the broker and indexer read for their chain config, so
    ///      addresses are never copy-pasted between components by hand.
    function _writeDeploymentFile(Erc8004Deployer.Deployment memory d, address deployer) internal {
        string memory json = string.concat(
            "{\n",
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n",
            '  "owner": "',
            vm.toString(deployer),
            '",\n',
            '  "identityRegistry": "',
            vm.toString(d.identityRegistry),
            '",\n',
            '  "reputationRegistry": "',
            vm.toString(d.reputationRegistry),
            '",\n',
            '  "validationRegistry": "',
            vm.toString(d.validationRegistry),
            '"\n',
            "}\n"
        );

        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        vm.writeFile(path, json);
        console2.log("wrote", path);
    }
}
