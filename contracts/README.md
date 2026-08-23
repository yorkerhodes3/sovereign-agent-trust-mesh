# contracts

Solidity for SATM. Built with Foundry; the ERC-8004 registries are vendored, not
reimplemented ([ADR-0004](../docs/adr/0004-foundry-with-vendored-registries.md)).

## Layout

```
src/
  interfaces/     IAgentMandate, IComplianceProvider   verbatim ERC-8226
                  ISatmAgentMandate                    SATM extensions, kept separate
                  IIdentityRegistry                    narrow read view of ERC-8004
  bootstrap/      SatmBootstrapUUPS, Erc8004Deployer   proxy stand-up used by tests AND deploys
  mandate/        AgentMandate, ComplianceProvider     Phase 4
  assets/         TreasuryNote, EquityNote, MockUSD    Phase 4
  settlement/     SettlementEscrow                     Phase 5
  validation/     ReplayValidator                      Phase 4
  audit/          AuditAnchor (L1)                     Phase 5
vendor/erc8004/   pinned upstream copy, CC0            DO NOT EDIT
test/
  integration/    behaviour of the real vendored registries
  conformance/    one test per ERC-8226 MUST clause    Phase 4
  extensions/     SATM's stricter additions            Phase 4
  invariant/      fuzz/invariant suites                Phase 4
script/           deployment
```

## Quick start

```bash
forge soldeer install     # restore locked dependencies
forge build
forge test -vv
```

Or from the repository root, `make test` / `.\make.ps1 test`.

## What Phase 0 actually proves

Everything below was executed, not just written:

| Check | Result |
| --- | --- |
| Vendored registries compile against pinned OpenZeppelin 5.1.0 | pass |
| `forge test` | **18/18 pass** |
| Registries deploy to a live anvil and answer calls | pass (chainId 31337) |
| Vendored sources byte-identical to pinned upstream | pass |
| `forge fmt --check` | pass |

The 18 tests are spike **S-4** from [PLAN.md](../PLAN.md), promoted from a
throwaway investigation into a permanent regression suite. They exist because
several SATM security properties are asserted in the specification as facts about
ERC-8004; if one of them is false, the design is wrong rather than merely buggy.

Two are worth calling out:

- **`test_agentWallet_isClearedOnTransfer`** — the load-bearing one. Threat TH-5
  and negative control N-7 both rest on ERC-8004 clearing `agentWallet` when the
  agent NFT is transferred, and [ADR-0003](../docs/adr/0003-agentwallet-is-the-rams-agent-address.md)
  calls that behaviour "free". It is only free if it is real. It is.

- **`test_sybil_threeSelfRegisteredAgentsSatisfyDistinctClientCount`** — proves a
  *weakness* rather than a guarantee. An attacker registers three agents for the
  price of three transactions and satisfies `minDistinctClients = 3` with a
  fabricated 100/100 score. This is why the reviewer allow-list has to be curated
  rather than a headcount ([SPECIFICATION.md §5.3](../SPECIFICATION.md)), and the
  test pins that reasoning to executable evidence so it cannot quietly regress.

## Two non-obvious constraints

**`via_ir = true` is required, not a preference.**
`ReputationRegistryUpgradeable.giveFeedback` takes eight parameters and hits
"stack too deep" under the legacy code generator. Turning IR off does not slow the
build down, it breaks it.

**`evm_version = "cancun"` is required.**
`TreasuryNote` carries agent context in transient storage (EIP-1153) so the
mandate hook cannot be spoofed ([SPECIFICATION.md §7.3.1](../SPECIFICATION.md)).

## The proxy bootstrap dance

The vendored registries cannot be initialized directly. Their `initialize()` is
`reinitializer(2) onlyOwner` and never calls `__Ownable_init`, so an owner must
already exist. Upstream solves this with `MinimalUUPS`, which hard-codes the owner
to one address for their vanity-address scheme — unusable on an ephemeral devnet.

`SatmBootstrapUUPS` is the same contract with the owner parameterised. Sequence:

1. deploy bootstrap implementation, put an `ERC1967Proxy` in front of it
2. bootstrap's `initialize` sets the owner
3. upgrade the proxy to the real registry implementation
4. call the registry's own `initialize`

`Erc8004Deployer` encapsulates this and is used by **both** the tests and the
deploy script, so tests cannot pass against a deployment shape that production
never uses.

## vendor/ is immutable

`vendor/erc8004/` mirrors upstream at the commit recorded in
[`vendor/erc8004/UPSTREAM`](vendor/erc8004/UPSTREAM). CI re-fetches each file and
fails on any diff. If SATM needs different behaviour, extend or wrap it in `src/`.

Check locally with `make verify-vendor` / `.\make.ps1 verify-vendor`.

## Deploying

Local devnet:

```bash
anvil --port 8545 &
PRIVATE_KEY=0xac09...ff80 forge script script/DeployRegistries.s.sol \
  --rpc-url http://127.0.0.1:8545 --broadcast
```

Addresses are written to `deployments/<chainId>.json` for the broker and indexer
to read, so they are never hand-copied between components.

On **public testnets**, do not deploy Identity or Reputation — canonical
singletons already exist and SATM must use them to interoperate with the real
ERC-8004 ecosystem:

| Registry | Testnet address |
| --- | --- |
| IdentityRegistry | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |
| ReputationRegistry | `0x8004B663056A597Dffe9eCcC1965A193B7388713` |

The Validation Registry has no canonical deployment and its section of the ERC is
still being revised with the TEE community, so SATM deploys its own everywhere and
keeps use of it behind a port.
