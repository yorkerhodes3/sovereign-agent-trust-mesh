# Sovereign Agent Trust Mesh (SATM)

> Combining Google SAM and Ethereum agent registries into a cross-enterprise agent economy.

AI agents can already talk to each other and invoke tools. What they cannot do is **trust each
other across organizational boundaries** — answer "who owns this agent, what authority does it
hold, what has it actually done, and what proof exists?" without a pre-existing relationship.

SATM is a prototype that answers those questions by joining three things that do not currently
connect:

| Layer | Technology | Gives us |
| --- | --- | --- |
| Transport | [Google SAM](https://github.com/google/sam) | Zero-config P2P mesh, cryptographic node identity, MCP as the agent API |
| Identity & trust | [ERC-8004](https://ercs.ethereum.org/ERCS/erc-8004) | Portable agent identity, reputation, independent validation |
| Authority | [ERC-8226](https://eips.ethereum.org/EIPS/eip-8226) | Machine-verifiable, scoped, capped, time-bounded delegation |

---

## The missing joint

SAM has no notion of global reputation or verifiable mandates. ERC-8004 has no transport.
ERC-8226 has neither identity nor transport. Nothing binds a **libp2p PeerID** to an on-chain
**`agentId`**, so on-chain trust cannot gate mesh traffic, and a mandate granted to an address
cannot be enforced against a network connection.

**That binding — and the enforcement machinery around it — is what this prototype builds.**

```
PeerID ⟷ Agent Mesh Binding ⟷ agentId ⟷ agentWallet ⟷ RAMS mandates
         (dual-signed, replay-protected, expiring)
```

A binding is one canonical document signed **twice**: by the node's libp2p host key (proving it
controls the PeerID) and by the agent's ERC-8004 `agentWallet` via EIP-712 (proving it controls
the on-chain identity). The on-chain registration file independently advertises the same PeerID,
so discovery can start from the chain — and the registry itself must be on the broker's
allow-list, or both signatures could be valid against a registry the attacker deployed.

Forging a binding requires both keys. And because ERC-8004 **clears `agentWallet` when the agent
NFT is transferred**, selling an agent revokes its mesh access and its ability to move assets
automatically — with no SATM-specific logic.

Fail-closed is stated precisely rather than absolutely: **asset-moving authorization fails closed
unconditionally**; everything else fails closed except within explicitly bounded, logged staleness
windows.

---

## Documents

| Document | What it covers |
| --- | --- |
| [CONCEPT-BRIEF.md](CONCEPT-BRIEF.md) | The original vision and six-plane architecture |
| **[SPECIFICATION.md](SPECIFICATION.md)** | Full technical specification: binding protocol, trust tiers, components, contracts, flows, threat model, conformance |
| **[PLAN.md](PLAN.md)** | Phased implementation plan, spikes, work breakdown, risk register, milestones |
| [docs/DEMO.md](docs/DEMO.md) | The scripted end-to-end scenario, including 18 negative controls |
| **[docs/SPIKE-FINDINGS.md](docs/SPIKE-FINDINGS.md)** | **Phase 1 results — what was tested against a real SAM mesh, what held, and what didn't** |
| [docs/RESEARCH-NOTES.md](docs/RESEARCH-NOTES.md) | Every upstream fact the design relies on, with citations |
| [docs/adr/](docs/adr) | Architecture decision records |

**Start with [SPECIFICATION.md §4](SPECIFICATION.md)** — the Agent Mesh Binding is the core
contribution; everything else composes existing standards.

---

## Architecture at a glance

```
   ORG A                          ORG B
 ┌─────────┐                    ┌─────────┐
 │  Agent  │                    │  Agent  │
 └────┬────┘                    └────▲────┘
      │ MCP                          │ MCP
 ┌────▼──────────┐              ┌────┴──────────┐
 │ satm-sidecar  │  PDP: tier + mandate checks  │
 └────┬──────────┘              └────▲──────────┘
      │ MCP                          │ MCP
 ┌────▼────┐   libp2p / Noise   ┌────┴────┐
 │sam-node │◄══════════════════►│sam-node │
 └────┬────┘  Biscuit-authorized└────┬────┘
      │                              │
      └──────► sam-control-plane ◄───┘
                     ▲
                     │ approve / policies / revoke
              ┌──────┴───────┐
              │ satm-broker  │◄── satm-indexer ──┐
              └──────┬───────┘                   │
                     │ anchor                    │ logs
                     ▼                           │
              L1: AuditAnchor        L2: ERC-8004 registries,
                                         RAMS mandate, regulated
                                         asset, settlement escrow
```

Enforcement happens at **two independent points** — admission (broker → control plane, node
Datalog) and use (sidecar, and authoritatively the on-chain transfer hook). See
[ADR-0005](docs/adr/0005-two-sided-enforcement.md).

---

## What the demo proves

Happy path: a treasury agent with no prior relationship discovers custodians on-chain, ranks them
by Sybil-resistant reputation, connects over an authenticated mesh that admits only bound agents,
proves its delegated authority, executes a regulated asset purchase the asset contract validates
atomically, settles in stablecoin, publishes reputation backed by proof of payment, and anchors
the audit trail to L1.

And ten things that **must fail**, each at a named layer:

| | Attack | Denied by |
| --- | --- | --- |
| N-1 | Unbound node joins the mesh | Broker enrollment gate |
| N-2 | Node claims another agent's `agentId` | Binding check B9 (wallet signature) |
| N-3 | Under-tiered caller reaches a custody service | Node attenuation + sidecar |
| N-4 | Mandated agent buys equities | `canExecute` — wrong asset |
| N-5 | Agent exceeds cumulative cap | Asset's `canExecute` guard; `recordExecution` independently |
| N-6 | Mandate revoked mid-session | Next block |
| N-7 | Agent NFT sold to an attacker | `agentWallet` cleared → asset reverts, binding revoked |
| N-8 | Sybil: attacker cross-reviews three of their own registered agents | Curated reviewer roster |
| N-9 | Binding replayed on another mesh | Signed `meshId` + single-use nonce |
| N-10 | Chain RPC unavailable | Degraded mode denies |
| N-11 | Binding names an attacker-deployed registry | Registry allow-list (B2a) |
| N-12 | Call attestation replayed or arguments mutated | Target + `argsHash` binding |
| N-13 | Caller spoofs its own identity to the broker | `self` taken from the authenticated channel |
| N-14 | Node quietly decommissioned but still calling | Reconciliation re-validates the registration file |
| N-15 | Principal's KYC revoked after the mandate was granted | Asset re-checks `checkPrincipal` |
| N-16 | Old wallet registers a fresh `agentId` to reuse a stale mandate | Immutable on-chain agent-identity pin |
| N-17 | Agent wallet moves tokens via ERC-20 `transferFrom` | Asset is transfer-restricted; no open paths |
| N-18 | Read-tool attestation presented to an asset tool | Signed `service`/`tool` compared to the request |

A trust prototype that only demonstrates the happy path proves nothing.

---

## Status

**Phase 0 complete. Phase 1 spikes complete.** The contract layer is verified, and every
blocking assumption about SAM has now been tested against a real mesh.

| Component | State |
| --- | --- |
| Specification, plan, ADRs | Complete |
| Foundry project + vendored ERC-8004 registries | **Working — 18/18 tests pass** |
| ERC-8226 interfaces (verbatim) + SATM extension interfaces | Compiling |
| Registry deployment to a live chain | **Verified on anvil** |
| CI (Solidity build/test/lint + vendor integrity) | **Green on a clean Linux runner** |
| **Phase 1 spikes S-1…S-5** | **All closed against a real SAM mesh** |
| Devnet compose | Corrected from spike findings; still not executed (no Docker) |
| Broker, indexer, sidecar, agents | Not started (Phases 2–5) |

### The result the design depended on

**S-2 passed.** Node-level attenuation really does evaluate the *caller's*
control-plane-attested labels, and denies at the transport handshake:

```
[Auth] AuthZ Denied 12D3KooWGRdG…: biscuit: verification failed:
  failed to verify check #1: check if label("erc8004.agent_id", "42")
```

A peer attesting `agent_id=42` got the full tool catalogue; a peer attesting `777` was
refused before any payload was read — and could not even enumerate the node's services.
Had this failed, [ADR-0001](docs/adr/0001-integrate-via-control-plane-not-fork.md), the
defence-in-depth model, and negative control N-3 would all have needed reworking.

Two other findings changed the design rather than confirming it:

- **S-1**: the spec described a "primary" label path that **does not exist**. Labels are
  declared by the node and attested by the admin at approval. The trust property is
  unchanged — approval is still the gate — but §6.1.3 was wrong and is now corrected.
- **S-5**: SAM does **not** pass caller identity to a local MCP service. That makes the
  Call Attestation *necessary*, not defence-in-depth.

Full evidence, including a blocking upstream defect found along the way, is in
[docs/SPIKE-FINDINGS.md](docs/SPIKE-FINDINGS.md).

---

## Ground rules

1. **No fork of SAM.** Integration uses documented HTTP endpoints and `sam-node.yaml` only
   ([ADR-0001](docs/adr/0001-integrate-via-control-plane-not-fork.md)).
2. **The chain is the source of truth; the mesh caches.** SAM labels and policy are a projection
   with bounded staleness, never an independent authority.
3. **Fail closed, with bounded and audited exceptions.** Asset movement never proceeds on stale
   or unverifiable data; other decisions may, only within named windows, and always logged.
4. **On-chain enforcement is authoritative for value.** Off-chain checks fail fast and save gas;
   the asset contract re-checks atomically and authenticates the agent itself.
5. **Promotions are slow, demotions are immediate.**

---

## Prerequisites

Go 1.25+ · Foundry · Python 3.12 · Docker · Make (see [.tool-versions](.tool-versions))

Phase 0's contract work needs **only Foundry**:

```bash
cd contracts && forge soldeer install && forge test
```

Or from the repository root — `make` on Unix, `make.ps1` on Windows, same targets:

```bash
make test            # contract suite
make devnet-up       # both anvil chains + deployed registries
make verify-vendor   # confirm vendor/ matches the pinned upstream commit
make ci              # everything CI runs
```

```powershell
.\make.ps1 test      # Windows equivalent — `make` is rarely installed there
```

The full devnet (Postgres, IPFS, Dex, SAM control plane and router) additionally
needs Docker and lands with Phase 1:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

---

## Licence and provenance

SATM-authored work in this repository is licensed under **Apache-2.0** — see [LICENSE](LICENSE).
Apache-2.0 was chosen for its express patent grant, which matters for a protocol specification
others may implement, and because it is compatible with everything SATM builds on.

Upstream components retain their own terms:

| Component | Licence | How SATM uses it |
| --- | --- | --- |
| [Google SAM](https://github.com/google/sam) | Apache-2.0 | Consumed **unforked**, via documented HTTP and YAML seams ([ADR-0001](docs/adr/0001-integrate-via-control-plane-not-fork.md)). No SAM source is vendored. |
| [ERC-8004 registry contracts](https://github.com/erc-8004/erc-8004-contracts) | CC0 | Vendored at a pinned commit ([ADR-0004](docs/adr/0004-foundry-with-vendored-registries.md)) |
| ERC-8004 / ERC-8226 specification text | CC0 | Referenced, and implemented from |

Third-party attributions are recorded in [NOTICE](NOTICE) as components are vendored.

ERC-8226 is a **Draft** EIP with no public reference implementation. Per project direction it is
treated as normative and assumed to be implemented; SATM implements it from the EIP text and
backs it with a conformance suite containing one test per MUST clause
([PLAN.md §6.2](PLAN.md)). SATM's own stricter additions are isolated in a separate extension
suite so conformance and extensions are never conflated.
