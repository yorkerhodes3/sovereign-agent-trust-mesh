// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {IdentityRegistryUpgradeable} from "erc8004/IdentityRegistryUpgradeable.sol";

/// @title SeedBrokerFixture
/// @notice Puts known agent state on a running devnet so the broker's Go chain client
///         can be tested against REAL contract bytecode rather than a stub.
///
/// @dev The Go unit tests drive `chainrpc` with a scripted JSON-RPC server, which proves
///      the client handles responses correctly but says nothing about whether the calldata
///      it builds actually hits the intended functions. `getAgentWallet(uint256)` in
///      particular has no publicly documented selector to pin against, so a hand-rolled
///      encoding bug would be invisible to the unit tests and fail only in production.
///      This fixture closes that gap.
///
///      Usage:
///
///        anvil --port 8545 &
///        forge script script/DeployRegistries.s.sol --rpc-url http://127.0.0.1:8545 \
///          --broadcast --private-key $PK
///        forge script script/SeedBrokerFixture.s.sol --rpc-url http://127.0.0.1:8545 \
///          --broadcast --private-key $PK
contract SeedBrokerFixture is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address operator = vm.addr(pk);

        // Anvil account #1. A well-known devnet address, used purely as a transfer target.
        address buyer = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

        string memory deploymentPath = string.concat("deployments/", vm.toString(block.chainid), ".json");
        string memory deployment = vm.readFile(deploymentPath);
        address identityAddr = vm.parseJsonAddress(deployment, ".identityRegistry");
        IdentityRegistryUpgradeable identity = IdentityRegistryUpgradeable(identityAddr);

        string memory liveURI = "https://example.test/agents/live.json";

        vm.startBroadcast(pk);

        // Agent 1: a normal, healthy registration.
        uint256 liveAgentId = identity.register(liveURI);

        // Agent 2: registered then SOLD. After the transfer `agentWallet` must read as the
        // zero address -- the property TH-5 and ADR-0003 rest on. Asserting it over real
        // JSON-RPC proves the broker will actually observe the revocation, not just that
        // Solidity-level tests do.
        uint256 soldAgentId = identity.register("https://example.test/agents/sold.json");
        identity.transferFrom(operator, buyer, soldAgentId);

        vm.stopBroadcast();

        console2.log("=== broker fixture seeded ===");
        console2.log("identityRegistry ", identityAddr);
        console2.log("liveAgentId      ", liveAgentId);
        console2.log("soldAgentId      ", soldAgentId);

        string memory json = string.concat(
            "{\n",
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n",
            '  "identityRegistry": "',
            vm.toString(identityAddr),
            '",\n',
            '  "operator": "',
            vm.toString(operator),
            '",\n',
            '  "buyer": "',
            vm.toString(buyer),
            '",\n',
            '  "liveAgentId": ',
            vm.toString(liveAgentId),
            ",\n",
            '  "liveAgentURI": "',
            liveURI,
            '",\n',
            '  "soldAgentId": ',
            vm.toString(soldAgentId),
            ",\n",
            '  "absentAgentId": 999999\n',
            "}\n"
        );

        string memory path = string.concat("deployments/broker-fixture-", vm.toString(block.chainid), ".json");
        vm.createDir("deployments", true);
        vm.writeFile(path, json);
        console2.log("wrote", path);
    }
}
