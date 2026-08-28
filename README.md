# Sovereign Agent Trust Mesh (SATM)

> Combining Google SAM and Ethereum agent registries into a cross-enterprise agent economy.

**📖 [Read the explainer →](https://yorkerhodes3.github.io/sovereign-agent-trust-mesh/)** — the
short, illustrated version of everything below.

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
| **[Explainer site](https://yorkerhodes3.github.io/sovereign-agent-trust-mesh/)** | **The illustrated short version — start here** ([source](site/)) |
| [CONCEPT-BRIEF.md](CONCEPT-BRIEF.md) | The original vision and six-plane architecture |
| **[SPECIFICATION.md](SPECIFICATION.md)** | Full technical specification: binding protocol, trust tiers, components, contracts, flows, threat model, conformance |
| **[PLAN.md](PLAN.md)** | Phased implementation plan, spikes, work breakdown, risk register, milestones |
| **[BACKLOG.md](BACKLOG.md)** | **What is built, what is not, and precisely what each remaining item needs** |
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

**Phases 0 and 1 complete. Phase 2 is 11 of 14 tasks done** — the whole
admission path works end to end against real ERC-8004 bytecode, and bindings
are revocable.

| Component | State |
| --- | --- |
| Specification, plan, ADRs | Complete |
| Foundry project + vendored ERC-8004 registries | **Working — 18/18 tests pass** |
| ERC-8226 interfaces (verbatim) + SATM extension interfaces | Compiling |
| Registry deployment to a live chain | **Verified on anvil** |
| CI (Solidity + Go) | **Green**, incl. `-race`, a live-chain job, and a Postgres service container |
| **Phase 1 spikes S-1…S-5** | **All closed against a real SAM mesh** |
| **Agent Mesh Binding verifier (B1–B15)** | **Working** — one test per check |
| **Broker chain client, fetcher, stores, HTTP API** | **Working** — 9 end-to-end tests against live registries |
| **Call Attestation (V1–V8)** | **Working** — 41 tests, one per check |
| **Reconciliation loop** | **Working** — proven on a live chain |
| `satm-sidecar` inbound authorization | Working; **outbound returns 501** pending the Phase 3 trust plane |
| Enrollment gate, label projection, `satm-cli` | Not started — see [BACKLOG.md §3](BACKLOG.md) |
| Devnet compose | Corrected from spike findings; still not executed (no Docker) |
| Indexer, mandates, agents | Not started (Phases 3–5) |

For the full picture of what remains and exactly what each item needs, see
**[BACKLOG.md](BACKLOG.md)**.

### On-chain state now controls mesh access

This is the claim the concept brief says nothing today delivers, and it is now
demonstrated by an automated test against a live chain:

```
agent registered and bound
  → NFT transferred with `cast send ... transferFrom`
  → next reconcile sweep
  → binding revoked, reason binding.agent_wallet_unset
```

Nothing SATM-specific tracks the sale. ERC-8004 zeroes `agentWallet` on
transfer, the reconciler re-reads it, and check B7 fails. The test asserts the
on-chain wallet actually cleared *first*, so a failure is attributable to the
reconciler rather than to a failed transaction.

Two negative controls sit alongside it, and they matter as much as the positive
case: repeated sweeps leave a healthy binding untouched, and a dead RPC endpoint
revokes **nothing**. Treating an outage as a verdict would let one bad afternoon
at a provider revoke the entire mesh.

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

Full evidence, including a blocking upstream defect
([google/sam#297](https://github.com/google/sam/issues/297)), is in
[docs/SPIKE-FINDINGS.md](docs/SPIKE-FINDINGS.md).

### The two mechanisms this project is about

**The Agent Mesh Binding** ties a libp2p PeerID to an on-chain `agentId`. One
test is worth reading in particular: `B2a_RejectsAttackerDeployedRegistry`. The
attacker deploys their own ERC-8004-shaped registry, mints themselves
`agentId 42` with a wallet they control, publishes a matching registration file,
and signs both proofs correctly. The submission is **internally consistent** —
every other check passes. Only the registry allow-list stops it, which is why
the EIP-712 domain is derived from *our* allow-list and never from the submitted
document.

**The Call Attestation** answers "who is calling?" per tool call. Spike S-5
proved this is not optional: SAM authenticates the peer at the transport layer
but does not pass that identity to a locally-spawned service, so without an
attestation any caller could name someone else's CAID and inherit their
authority. Check V6 is what makes the hot signing key revocable with no
revocation list — the caller's binding id is inside the signature and must be
current, so re-binding an agent invalidates every outstanding attestation signed
under the old key.

See [services/broker/README.md](services/broker/README.md) and
[services/sidecar/README.md](services/sidecar/README.md).

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
