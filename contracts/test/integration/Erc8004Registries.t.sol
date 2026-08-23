// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Erc8004Deployer} from "satm/bootstrap/Erc8004Deployer.sol";
import {IdentityRegistryUpgradeable} from "erc8004/IdentityRegistryUpgradeable.sol";
import {ReputationRegistryUpgradeable} from "erc8004/ReputationRegistryUpgradeable.sol";
import {ValidationRegistryUpgradeable} from "erc8004/ValidationRegistryUpgradeable.sol";

/// @title Erc8004RegistriesTest
/// @notice Executable verification of the ERC-8004 behaviours that SATM's design depends on.
///
/// @dev This is spike **S-4** from PLAN.md, promoted into a permanent regression suite.
///
///      The point is NOT to test upstream's code for its own sake. It is that several
///      SATM security properties are stated in the specification as though they are facts
///      about ERC-8004, and if any of them is false the design is wrong rather than merely
///      buggy. Each test below is annotated with the specification claim it discharges.
///
///      Most important: `test_agentWallet_isClearedOnTransfer`. Threat TH-5 and negative
///      control N-7 both rest entirely on it, and ADR-0003 calls the behaviour "free".
///      It is only free if it is real.
contract Erc8004RegistriesTest is Test {
    IdentityRegistryUpgradeable internal identity;
    ReputationRegistryUpgradeable internal reputation;
    ValidationRegistryUpgradeable internal validation;

    address internal constant OWNER = address(0xA11CE);
    address internal alice = makeAddr("alice"); // agent operator
    address internal bob = makeAddr("bob"); // buyer of the agent NFT
    address internal client1 = makeAddr("client1");
    address internal client2 = makeAddr("client2");
    address internal validator = makeAddr("validator");

    /// @dev keccak256("AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)")
    bytes32 internal constant AGENT_WALLET_SET_TYPEHASH =
        keccak256("AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)");

    function setUp() public {
        vm.startPrank(OWNER);
        Erc8004Deployer.Deployment memory d = Erc8004Deployer.deployAll(OWNER);
        vm.stopPrank();

        identity = IdentityRegistryUpgradeable(d.identityRegistry);
        reputation = ReputationRegistryUpgradeable(d.reputationRegistry);
        validation = ValidationRegistryUpgradeable(d.validationRegistry);
    }

    // -----------------------------------------------------------------------
    // Deployment
    // -----------------------------------------------------------------------

    /// @dev Sanity: the three-step bootstrap dance actually produced live registries.
    function test_deployment_wiresRegistriesTogether() public view {
        assertEq(reputation.getIdentityRegistry(), address(identity), "reputation -> identity");
        assertEq(validation.getIdentityRegistry(), address(identity), "validation -> identity");
        assertEq(identity.owner(), OWNER, "identity owner");
    }

    // -----------------------------------------------------------------------
    // Identity Registry
    // -----------------------------------------------------------------------

    /// @dev SPECIFICATION.md 4.6 B6/B7 assume `register()` yields an agentId whose
    ///      `agentWallet` is immediately readable and equal to the registrant.
    function test_register_setsAgentWalletToRegistrant() public {
        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent-alice");

        assertEq(identity.ownerOf(agentId), alice, "owner");
        assertEq(identity.getAgentWallet(agentId), alice, "agentWallet seeded to registrant");
        assertEq(identity.tokenURI(agentId), "ipfs://agent-alice", "agentURI");
    }

    /// @dev agentIds are assigned incrementally from 0. The broker uses agentId as part of
    ///      the CAID primary key, so a non-deterministic scheme would break the trust store.
    function test_register_assignsIncrementingIds() public {
        vm.prank(alice);
        uint256 first = identity.register("ipfs://a");
        vm.prank(bob);
        uint256 second = identity.register("ipfs://b");

        assertEq(second, first + 1, "ids increment");
    }

    /// @notice THE LOAD-BEARING TEST.
    /// @dev SPECIFICATION.md 7.3.2 and ADR-0003 claim an ERC-721 transfer clears
    ///      `agentWallet`, which is what makes a sold agent's mandates and payouts inert
    ///      with no SATM-specific bookkeeping. Threat TH-5 and negative control N-7 both
    ///      depend on it. If this test ever fails, the design is broken, not the test.
    function test_agentWallet_isClearedOnTransfer() public {
        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent");
        assertEq(identity.getAgentWallet(agentId), alice, "precondition: wallet set");

        vm.prank(alice);
        identity.transferFrom(alice, bob, agentId);

        assertEq(identity.ownerOf(agentId), bob, "ownership moved");
        assertEq(identity.getAgentWallet(agentId), address(0), "agentWallet CLEARED on transfer");
    }

    /// @dev The clear must NOT fire on mint, or every fresh registration would be unusable.
    ///      `_update` distinguishes the two by checking `from != address(0)`.
    function test_agentWallet_isNotClearedOnMint() public {
        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent");
        assertEq(identity.getAgentWallet(agentId), alice, "mint must not clear");
    }

    /// @dev SPECIFICATION.md 4.4 reuses this exact proof pattern for the AMB wallet
    ///      signature, on the argument that an operator already has the key management
    ///      for it. That argument only holds if the flow works.
    function test_setAgentWallet_acceptsEip712SignatureFromNewWallet() public {
        (address newWallet, uint256 newWalletPk) = makeAddrAndKey("newWallet");

        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent");

        uint256 deadline = block.timestamp + 60;
        bytes32 structHash =
            keccak256(abi.encode(AGENT_WALLET_SET_TYPEHASH, agentId, newWallet, alice, deadline));
        bytes32 digest = _domainSeparatorHash(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newWalletPk, digest);

        vm.prank(alice);
        identity.setAgentWallet(agentId, newWallet, deadline, abi.encodePacked(r, s, v));

        assertEq(identity.getAgentWallet(agentId), newWallet, "wallet rotated");
    }

    /// @dev A signature from anyone other than the incoming wallet must fail. This is what
    ///      stops an agent owner from nominating a wallet they do not control.
    function test_setAgentWallet_rejectsSignatureFromWrongKey() public {
        (address newWallet,) = makeAddrAndKey("newWallet");
        (, uint256 attackerPk) = makeAddrAndKey("attacker");

        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent");

        uint256 deadline = block.timestamp + 60;
        bytes32 structHash =
            keccak256(abi.encode(AGENT_WALLET_SET_TYPEHASH, agentId, newWallet, alice, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, _domainSeparatorHash(structHash));

        vm.prank(alice);
        vm.expectRevert(bytes("invalid wallet sig"));
        identity.setAgentWallet(agentId, newWallet, deadline, abi.encodePacked(r, s, v));
    }

    /// @dev The registry bounds how far ahead a deadline may sit (MAX_DEADLINE_DELAY, 5 min).
    ///      SATM's own binding documents are bounded for the analogous reason (check B1).
    function test_setAgentWallet_rejectsDistantDeadline() public {
        (address newWallet, uint256 newWalletPk) = makeAddrAndKey("newWallet");

        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent");

        uint256 deadline = block.timestamp + 1 days; // beyond MAX_DEADLINE_DELAY
        bytes32 structHash =
            keccak256(abi.encode(AGENT_WALLET_SET_TYPEHASH, agentId, newWallet, alice, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newWalletPk, _domainSeparatorHash(structHash));

        vm.prank(alice);
        vm.expectRevert(bytes("deadline too far"));
        identity.setAgentWallet(agentId, newWallet, deadline, abi.encodePacked(r, s, v));
    }

    /// @dev `agentWallet` is a RESERVED metadata key: it cannot be written through the
    ///      generic setter, only through the signature-checked path. Without this, the
    ///      whole wallet-proof mechanism would be bypassable.
    function test_setMetadata_cannotWriteReservedAgentWalletKey() public {
        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent");

        vm.prank(alice);
        vm.expectRevert();
        identity.setMetadata(agentId, "agentWallet", abi.encodePacked(bob));
    }

    // -----------------------------------------------------------------------
    // Reputation Registry
    // -----------------------------------------------------------------------

    /// @dev Feedback indices are 1-based. The indexer's `feedback` table keys on
    ///      (agentId, client, feedbackIndex); an off-by-one would silently drop the
    ///      first review of every agent.
    function test_giveFeedback_isOneIndexed() public {
        uint256 agentId = _registerAgent(alice);

        vm.prank(client1);
        reputation.giveFeedback(agentId, 87, 0, "starred", "custody", "", "", bytes32(0));

        assertEq(reputation.getLastIndex(agentId, client1), 1, "first feedback is index 1");

        (int128 value,, string memory tag1,, bool isRevoked) = reputation.readFeedback(agentId, client1, 1);
        assertEq(value, 87, "value");
        assertEq(tag1, "starred", "tag1");
        assertFalse(isRevoked, "not revoked");
    }

    /// @dev ERC-8004 forbids self-review: the submitter MUST NOT be the agent owner or an
    ///      approved operator. SPECIFICATION.md 5.3 relies on this as the ONE anti-Sybil
    ///      guarantee the protocol itself provides.
    function test_giveFeedback_rejectsSelfReviewByOwner() public {
        uint256 agentId = _registerAgent(alice);

        vm.prank(alice);
        vm.expectRevert();
        reputation.giveFeedback(agentId, 100, 0, "starred", "", "", "", bytes32(0));
    }

    /// @dev `getSummary` MUST be called with a non-empty client filter. The ERC calls this
    ///      out explicitly as a Sybil mitigation, and SPECIFICATION.md 5.3 builds the whole
    ///      curated-reviewer model on top of it.
    function test_getSummary_requiresNonEmptyClientFilter() public {
        uint256 agentId = _registerAgent(alice);

        vm.prank(client1);
        reputation.giveFeedback(agentId, 90, 0, "starred", "", "", "", bytes32(0));

        address[] memory empty = new address[](0);
        vm.expectRevert();
        reputation.getSummary(agentId, empty, "", "");

        address[] memory filtered = new address[](1);
        filtered[0] = client1;
        (uint64 count, int128 summary,) = reputation.getSummary(agentId, filtered, "", "");
        assertEq(count, 1, "count");
        assertEq(summary, 90, "summary");
    }

    /// @dev Revoked feedback must drop out of aggregation. The scoring engine
    ///      (SPECIFICATION.md 5.3) excludes `isRevoked` entries; this proves the on-chain
    ///      side agrees rather than the indexer having to special-case it.
    function test_revokeFeedback_removesEntryFromSummary() public {
        uint256 agentId = _registerAgent(alice);

        vm.prank(client1);
        reputation.giveFeedback(agentId, 10, 0, "starred", "", "", "", bytes32(0));
        vm.prank(client2);
        reputation.giveFeedback(agentId, 90, 0, "starred", "", "", "", bytes32(0));

        address[] memory clients = new address[](2);
        clients[0] = client1;
        clients[1] = client2;

        (uint64 countBefore, int128 sumBefore,) = reputation.getSummary(agentId, clients, "", "");
        assertEq(countBefore, 2, "two before");
        assertEq(sumBefore, 50, "mean of 10 and 90");

        vm.prank(client1);
        reputation.revokeFeedback(agentId, 1);

        (uint64 countAfter, int128 sumAfter,) = reputation.getSummary(agentId, clients, "", "");
        assertEq(countAfter, 1, "one after revoke");
        assertEq(sumAfter, 90, "only the surviving review counts");
    }

    /// @dev Distinct clients are tracked, which is what `minDistinctClients` reads.
    function test_getClients_tracksDistinctReviewers() public {
        uint256 agentId = _registerAgent(alice);

        vm.prank(client1);
        reputation.giveFeedback(agentId, 80, 0, "starred", "", "", "", bytes32(0));
        vm.prank(client1);
        reputation.giveFeedback(agentId, 85, 0, "starred", "", "", "", bytes32(0));
        vm.prank(client2);
        reputation.giveFeedback(agentId, 70, 0, "starred", "", "", "", bytes32(0));

        assertEq(reputation.getClients(agentId).length, 2, "two DISTINCT clients, not three reviews");
        assertEq(reputation.getLastIndex(agentId, client1), 2, "client1 left two reviews");
    }

    /// @notice Demonstrates why "distinct clients" alone is not a Sybil defence.
    /// @dev Negative control N-8 was rewritten during design review precisely because of
    ///      this: registration is permissionless, so an attacker mints three agents, has
    ///      them review a fourth, and satisfies `minDistinctClients = 3` for the price of
    ///      three transactions. The mitigation has to be a CURATED reviewer roster
    ///      (SPECIFICATION.md 5.3), not a headcount. This test pins that reasoning down.
    function test_sybil_threeSelfRegisteredAgentsSatisfyDistinctClientCount() public {
        uint256 target = _registerAgent(alice);

        address[] memory sybils = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            sybils[i] = makeAddr(string(abi.encodePacked("sybil", vm.toString(i))));
            // Each Sybil registers its own agent: cheap, permissionless, no gatekeeping.
            _registerAgent(sybils[i]);
            vm.prank(sybils[i]);
            reputation.giveFeedback(target, 100, 0, "starred", "", "", "", bytes32(0));
        }

        assertEq(reputation.getClients(target).length, 3, "headcount satisfied");

        (uint64 count, int128 summary,) = reputation.getSummary(target, sybils, "", "");
        assertEq(count, 3, "three reviews");
        assertEq(summary, 100, "perfect score, entirely fabricated");

        // The on-chain layer cannot distinguish these from genuine reviewers. Only an
        // off-chain curated roster can, which is why SATM weights w(client)=0 for
        // non-curated addresses instead of trusting the count.
    }

    // -----------------------------------------------------------------------
    // Validation Registry
    // -----------------------------------------------------------------------

    /// @dev Only the agent owner/operator may open a validation request.
    function test_validationRequest_mustComeFromAgentOwner() public {
        uint256 agentId = _registerAgent(alice);
        bytes32 requestHash = keccak256("request-1");

        vm.prank(bob);
        vm.expectRevert();
        validation.validationRequest(validator, agentId, "ipfs://req", requestHash);

        vm.prank(alice);
        validation.validationRequest(validator, agentId, "ipfs://req", requestHash);

        assertEq(validation.getAgentValidations(agentId).length, 1, "request recorded");
    }

    /// @dev Only the NAMED validator may answer. Otherwise anyone could self-validate.
    function test_validationResponse_mustComeFromNamedValidator() public {
        uint256 agentId = _registerAgent(alice);
        bytes32 requestHash = keccak256("request-1");

        vm.prank(alice);
        validation.validationRequest(validator, agentId, "ipfs://req", requestHash);

        vm.prank(bob);
        vm.expectRevert();
        validation.validationResponse(requestHash, 100, "", bytes32(0), "");
    }

    /// @dev The ERC permits repeated responses for one requestHash, to support progressive
    ///      finality (e.g. "soft" then "hard"). SPECIFICATION.md 6.2 therefore specifies
    ///      latest-response-wins per tag in the indexer; this proves the chain allows it.
    function test_validationResponse_supportsProgressiveFinality() public {
        uint256 agentId = _registerAgent(alice);
        bytes32 requestHash = keccak256("request-1");

        vm.prank(alice);
        validation.validationRequest(validator, agentId, "ipfs://req", requestHash);

        vm.prank(validator);
        validation.validationResponse(requestHash, 60, "", bytes32(0), "soft");
        (,, uint8 firstResponse,, string memory firstTag,) = validation.getValidationStatus(requestHash);
        assertEq(firstResponse, 60, "soft finality recorded");
        assertEq(firstTag, "soft", "soft tag");

        vm.prank(validator);
        validation.validationResponse(requestHash, 100, "", bytes32(0), "hard");
        (,, uint8 secondResponse,, string memory secondTag,) = validation.getValidationStatus(requestHash);
        assertEq(secondResponse, 100, "hard finality overwrites");
        assertEq(secondTag, "hard", "hard tag");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _registerAgent(address operator) internal returns (uint256 agentId) {
        vm.prank(operator);
        agentId = identity.register("ipfs://agent");
    }

    /// @dev Rebuilds the EIP-712 digest the registry computes internally.
    function _domainSeparatorHash(bytes32 structHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            identity.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
