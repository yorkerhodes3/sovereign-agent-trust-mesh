# ADR-0004: Foundry for SATM contracts, vendored ERC-8004 registries

**Status:** Accepted
**Date:** 2026-08-22

## Context

SATM needs two categories of contract:

1. **ERC-8004 registries** — already implemented and audited-by-community in
   `github.com/erc-8004/erc-8004-contracts` (CC0, Hardhat + Ignition, TypeScript, ships `abis/`),
   with deterministic deployments across many chains.
2. **New contracts** — an ERC-8226 (RAMS) implementation, a RAMS-aware regulated asset, escrow,
   a validator, and an L1 audit anchor. No public ERC-8226 reference implementation exists, so
   this is from-spec work that needs heavy property and invariant testing.

Choosing one toolchain for both would mean either writing the new contracts in Hardhat (weak
fuzz/invariant story for this kind of state-machine work) or re-implementing the registries in
Foundry (pointless divergence from a canonical, widely deployed implementation).

## Decision

**Use Foundry for all SATM-authored contracts. Vendor the ERC-8004 registries as-is and consume
them through their published ABIs.**

- `contracts/vendor/erc8004/` holds the registry sources and ABIs at a pinned commit, with the
  CC0 notice retained.
- `contracts/src/` holds SATM-authored contracts, tested with `forge test`, `forge fuzz`, and
  `forge invariant`.
- On testnets with canonical deployments, SATM **uses the canonical addresses**
  (`0x8004A818BFB912233c491871b3d84c89A494BD9e` for IdentityRegistry,
  `0x8004B663056A597Dffe9eCcC1965A193B7388713` for ReputationRegistry) rather than deploying its
  own. On the local devnet it deploys the vendored sources.

## Consequences

**Positive**

- The prototype interoperates with the **real** ERC-8004 ecosystem on testnets, rather than with a
  private fork of it. An agent registered by SATM is visible to any other ERC-8004 tool.
- Foundry's fuzzing and invariant testing are well suited to the RAMS cap/expiry/freeze state
  machine, where the interesting bugs are in state transitions rather than in single calls.
- The ERC-8226 conformance suite (one test per MUST clause) is cheap to express and fast to run.

**Negative**

- Two toolchains in one repo. Mitigated by only ever *building* with Foundry — the vendored
  Hardhat project is a source and ABI reference, not part of the build.
- Vendored sources drift from upstream. Mitigated by pinning a commit and recording it in
  `contracts/vendor/erc8004/UPSTREAM`.

## Note on the Validation Registry

The published ERC-8004 address table lists **only Identity and Reputation**. No canonical
ValidationRegistry address exists, and the upstream README warns the validation section is "still
under active update and discussion with the TEE community".

SATM therefore deploys its own ValidationRegistry on every network, and isolates all use of it
behind a `ValidationPort` interface in the indexer and broker. Validation is deliberately kept off
the critical path ([PLAN.md R-5](../../PLAN.md)).
