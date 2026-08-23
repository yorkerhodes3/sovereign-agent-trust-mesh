# Sovereign Agent Trust Mesh — Implementation Plan

**Prototype codename:** SATM
**Version:** 0.1
**Companion documents:** [SPECIFICATION.md](SPECIFICATION.md) · [docs/RESEARCH-NOTES.md](docs/RESEARCH-NOTES.md) · [docs/DEMO.md](docs/DEMO.md) · [docs/adr/](docs/adr)

---

## 1. Strategy

### 1.1 What we are actually building

The prototype's value is **not** in re-implementing SAM, ERC-8004, or ERC-8226. All three exist
or are fully specified. The value is in the **joint** between them — the binding and enforcement
machinery described in [SPECIFICATION.md §4](SPECIFICATION.md) and §6.

The plan is therefore ordered by **risk retired per week**, not by architectural layer. We build
the binding first, because if the binding cannot be made to work against the real SAM control
plane, every other layer is decoration.

### 1.2 Sequencing principle

```
Phase 0  Foundations        ─ make the environment reproducible
Phase 1  Spikes             ─ retire the three unknowns that could invalidate the design
Phase 2  Identity plane     ─ AMB binding + enrollment gate      ← the core deliverable
Phase 3  Trust plane        ─ indexer, tiers, reputation ranking
Phase 4  Compliance plane   ─ RAMS contracts + enforcement
Phase 5  Settlement + audit ─ escrow, feedback, L1 anchoring
Phase 6  Demo + hardening   ─ scenario, negative controls, chaos, docs
```

Phases 3 and 4 can overlap once Phase 2 lands, because the contract work (Phase 4) has no
dependency on the mesh work (Phase 3). Phase 1 gates everything.

### 1.3 Working assumptions

These are decisions taken to keep the prototype moving. Each is reversible and recorded.

| # | Assumption | If wrong |
| --- | --- | --- |
| A-1 | ERC-8226 will be implemented substantially as drafted; we implement it ourselves since no public reference exists. | Conformance suite (§6.2) localises the change. |
| A-2 | Google SAM is consumed **unforked**, via released binaries/containers and documented HTTP + YAML seams. | Fallback is a thin fork with a rebase discipline; cost tracked as R-3. |
| A-3 | Identity/trust/compliance/settlement all live on **one L2** (Base Sepolia); audit anchors to **Ethereum Sepolia** as the L1 stand-in. | Cross-chain is explicitly out of scope for v0.1. |
| A-4 | Local development uses **Anvil** with all registries deployed locally; testnet is a later promotion step. | None — this is strictly additive. |
| A-5 | Agents are Python (SAM ships `sam-mcp-python`); infrastructure is Go; contracts are Foundry. | Language choices are per-component and independent. |
| A-6 | A2A is advertised but not exercised (SAM's A2A support is thin — research note 1.7). | Revisit when upstream matures; MCP carries negotiation meanwhile. |

### 1.4 Shape of the team

Sized for **2–3 engineers over ~10 weeks**. Roles are hats, not people:

- **Chain** — Solidity, Foundry, indexer
- **Mesh** — Go services, SAM integration, policy projection
- **Agents/Demo** — Python agents, scenario, docs

---

## 2. Phase 0 — Foundations (Week 1)

**Goal:** anyone can clone the repo and get a running mesh + chain in one command.

| ID | Task | Deliverable | Done when |
| --- | --- | --- | --- |
| P0-1 | Repo scaffold per [SPECIFICATION.md §17](SPECIFICATION.md) | Directory tree, licences, `CODEOWNERS`, `.editorconfig` | `tree` matches spec |
| P0-2 | Toolchain pinning | `.tool-versions` (Go 1.25+, Foundry, Python 3.12, Node for IPFS tooling) | CI installs cleanly on Linux + Windows |
| P0-3 | Local devnet compose | `deploy/compose/` — Anvil (L2 role), Anvil (L1 role), Postgres, IPFS (Kubo), Dex, `sam-control-plane`, `sam-router` | `make devnet-up` → all healthy |
| P0-4 | SAM bring-up | Two `sam-node` containers enrolled against the local control plane | `mcp-client -tool get_mesh_info` shows both peers |
| P0-5 | Contract skeleton | Foundry project, vendored ERC-8004 registries (CC0), deploy script | `forge test` green; registries deployed on both Anvils |
| P0-6 | CI | Build + unit test + lint for Go, Solidity, Python | Green on a trivial PR |
| P0-7 | Makefile UX | `devnet-up`, `devnet-down`, `test`, `test-e2e`, `demo`, `fmt`, `lint` | Documented in README |

**Exit criteria:** `make devnet-up && make demo-smoke` starts a two-node SAM mesh plus two chains
and prints both PeerIDs and the deployed registry addresses.

> **Note on P0-4:** the control plane MUST be started with `--auto-approve-enrollment=false` from
> day one. Building against auto-approval and switching later would hide the exact failure modes
> the broker must handle.

---

## 3. Phase 1 — De-risking Spikes (Week 1–2)

**Goal:** convert the three open unknowns into verified facts before committing to the design.
Each spike is timeboxed; each has a defined fallback already specified.

### S-1 — Enrollment approval and label attestation *(2 days, blocking)*

**Question (OI-1):** what exactly does `POST /admin/enrollments/{id}/approve` accept, and can the
approver attest labels at approval time?

**Method:** run `sam-control-plane` locally with manual approval; enroll a node; capture the
`GET /admin/enrollments` payload and experiment with the approve body; read
`internal/controlplane/server.go` `HandleAdminEnrollmentAction` and the enrollment storage model.

**Outputs:** a documented request/response schema; a Go client for the admin API; a decision
between the **primary** and **fallback** label paths in
[SPECIFICATION.md §6.1.3](SPECIFICATION.md).

**Fallback if labels cannot be attested at approval:** node declares labels at enrollment; broker
*validates* them against the verified binding and rejects on mismatch. Trust property is
identical because approval is the gate.

**Kill criterion:** if enrollment cannot be gated at all, escalate to A-2's fork fallback.

### S-2 — Node attenuation enforcement *(2 days, blocking)*

**Question:** does a `sam-node.yaml` `attenuation.checks` entry referencing `label(...)` actually
deny a caller lacking that label?

**Method:** two nodes; give node B an attenuation check
`check if label("erc8004.agent_id", $id)`; enroll node A **without** that label and node C
**with** it; attempt `call_remote_tool` from each.

**Expected:** A is denied at `WithBiscuitAuth`; C succeeds. This validates the read of
`internal/node/middleware.go:244-254` recorded in research note 1.4.

**Output:** a regression test in `tests/e2e/` that runs on every CI build, so an upstream SAM
change that breaks this assumption is caught immediately.

**Fallback:** if caller labels are not evaluated as expected, inbound enforcement moves entirely
to the sidecar. The design already tolerates this — node attenuation is defence in depth
([SPECIFICATION.md §10.3](SPECIFICATION.md)), not the sole gate.

### S-3 — Initiator-side trust *(1 day, non-blocking)*

**Question (OI-2):** does a SAM initiator evaluate the responder's returned
`AuthResponse.Biscuit` against local policy?

**Method:** inspect the client path in `internal/node/`; observe behaviour when calling a peer
whose labels violate local checks.

**Outcome either way:** the sidecar performs initiator-side checks regardless
([SPECIFICATION.md §6.3.2](SPECIFICATION.md)). This spike only determines whether we get a second
layer for free.

### S-4 — ERC-8004 registry behaviours *(2 days, parallel)*

**Method:** against the vendored registries on Anvil, write integration tests proving:
`register()` → `agentId`; `setAgentWallet` EIP-712 round trip; **`agentWallet` clears on
`transferFrom`**; self-feedback reverts; `getSummary` rejects an empty `clientAddresses`;
`revokeFeedback` excludes from reads; repeated `validationResponse` for one `requestHash`.

**Why it matters:** TH-5 (agent sold to attacker) and TH-4 (Sybil) mitigations both depend on these
being true in the *implementation*, not just in the prose.

### S-5 — Does SAM expose an authenticated caller PeerID to a local service? *(1 day, non-blocking)*

**Question:** when `sam-node` forwards an inbound MCP request to a locally-spawned service, does it
attach the authenticated caller PeerID (header, metadata, or environment)?

**Why it is separate from S-3:** S-3 asks whether the *initiator* evaluates the responder's
Biscuit. This asks whether the *responder's* local service learns who called. They are different
questions and an earlier draft conflated them.

**Method:** run two nodes; register a local MCP service on B; call it from A; inspect everything
the service receives.

**Outcome either way:** the Call Attestation (§6.3.3) already establishes caller identity
independently. A positive result only enables the optional **channel binding** check, upgrading
`attestation.requireChannelBinding` from `false` to `true`.

**Exit criteria for Phase 1:** all five spikes closed; OI-1/OI-2 resolved in
[SPECIFICATION.md §19](SPECIFICATION.md); any design changes merged before Phase 2 begins.

---

## 4. Phase 2 — Identity Plane and Agent Mesh Binding (Weeks 2–4)

**This is the core of the prototype.** Everything else composes existing standards.

| ID | Task | Detail | Acceptance |
| --- | --- | --- | --- |
| P2-1 | Binding document + canonicalisation | RFC 8785 JCS in Go; `type`/schema validation; **normative field encodings** (§4.3): lowercase-hex addresses, decimal-string `agentId` and `nonce`, RFC 3339 timestamps | Golden-vector tests; byte-identical canonicalisation across Go and Python; a checksummed-vs-lowercase address must produce the same CAID or be rejected, never silently differ |
| P2-2 | PeerID proof | Sign with libp2p host key; derive PeerID via **`peer.IDFromPublicKey` semantics**, not an ad-hoc multihash; require Ed25519 host keys | Unit tests incl. mismatched key, wrong PeerID, truncated sig, and a key whose raw-bytes hash collides with the claim but whose canonical derivation does not |
| P2-2a | **Registry allow-list (B2a)** | Reject any binding whose registry tuple is not allow-listed; derive all chain calls, the EIP-712 domain, the CAID, and every label from the matched tuple | An attacker-deployed ERC-8004-shaped registry minting `agentId 42` to itself is rejected before any chain read (TH-3a) |
| P2-3 | Wallet proof | EIP-712 `MeshBinding` typehash incl. `sidecarKey`; domain from the allow-listed tuple; verify via `SignatureChecker` semantics (EOA + ERC-1271) | Tests with EOA, Safe-style ERC-1271 mock, wrong signer, expired deadline, and a signature valid under a *different* domain |
| P2-4 | Hardened resolver | `agentURI` fetch: scheme allow-list, 256 KiB cap, 5 s timeout, redirect limit, private-range block, negative caching | SSRF test suite (TH-8); oversized/deep-JSON rejection (TH-9) |
| P2-5 | Registration file validation | `registrations[]` match, `services[]` `SAM` entry, `sam://` URI parser, `active` flag | Parser fuzz test; malformed-URI corpus |
| P2-6 | Full `verify_binding` (B1–B15) | Ordered checks, first-failure denial, reason codes; **TTL upper bound**; **nonce checked at B3, consumed atomically at B15** | One test per check, each proving denial in isolation; a concurrency test proving two simultaneous submissions of one nonce yield exactly one success; a test proving an unsigned submission cannot burn a nonce (TH-17) |
| P2-7 | Trust store | Postgres schema ([SPECIFICATION.md §6.2](SPECIFICATION.md)); migrations | Unique indexes on `(peer_id, mesh_id)` **and** `(caid, mesh_id)` where not revoked; `consumed_nonces` unique key |
| P2-8 | `POST /v1/bindings` | Nonce store, rate limiting, structured errors | Replay attempt returns `409` with `nonce.reused`; wallet already bound to another CAID returns `409 wallet.bound_elsewhere` (B9a) |
| P2-9 | Enrollment gate | Poll `/admin/enrollments`; match PeerID → binding; approve/reject; grace-period rejection | Unbound node is rejected after grace period; bound node is approved with labels |
| P2-10 | Label projection | Per S-1 outcome (primary or fallback) | Minted Biscuit contains `erc8004.agent_id`; verified by decoding the token |
| P2-11 | `satm-cli bind` | Key handling, sidecar keypair generation, doc construction, dual signing, submission | Operator can bind in one command from a fresh node |
| P2-12 | Reconciliation loop | `getAgentWallet` → `address(0)`; **full B10–B13 re-validation**; tier recompute; revoke via `/admin/revoke` | **Transfer the agent NFT → mesh access revoked within one interval**; **remove the `SAM` service entry → also revoked within one interval** (TH-16) |
| P2-13 | **Call attestation** | Sidecar keypair bound into the binding document; canonical-JSON + Ed25519 sign/verify; **all eight verifier checks V1–V8** (§6.3.3) incl. `service`/`tool` comparison, `callerBindingId` currency, and atomic `(callerBindingId, nonce)` consumption before forwarding | Attestation replayed at a different callee, escalated from a read tool to an asset tool, mutated args, signed under a superseded binding, or replayed after TTL — each rejected with a distinct reason (TH-7a/b/c); `/v1/authorize` ignores a body-supplied `self` |
| P2-14 | **Split authorize schemas** | Outbound takes `peer.peerId` (broker resolves it); inbound takes `peer.attestation`. Order is authorize → mint → send | A single-schema implementation requiring an attestation on outbound is impossible; regression test asserts the outbound path never needs one |

**Exit criteria (demonstrable):**

1. A node with a valid binding enrolls and receives a Biscuit carrying `erc8004.agent_id`.
2. A node **without** a binding is rejected and cannot join.
3. A node whose agent NFT is transferred loses mesh access within one reconcile interval (TH-5).
4. A binding document replayed against a second mesh is rejected (TH-3).
5. `satm_discover_agents` returns bound peers only.
6. A binding naming an attacker-deployed registry is rejected before any chain read (TH-3a).
7. A call attestation replayed at a different callee or with mutated arguments is rejected (TH-7a).

> Item 3 is the single most convincing demonstration in the prototype: it shows on-chain state
> changes propagating into live network access control, which is precisely the capability the
> concept brief says is missing today.

---

## 5. Phase 3 — Trust Plane (Weeks 4–6)

| ID | Task | Detail | Acceptance |
| --- | --- | --- | --- |
| P3-1 | Indexer core | Log subscription, `(txHash, logIndex)` idempotency, checkpointing | Restart mid-stream loses nothing, duplicates nothing |
| P3-2 | Reorg handling | Store `blockHash`; detect ancestry break; roll back and replay; confirmation depth before promotion | Anvil-forced reorg test: promotion reverts, demotion is immediate (TH-10) |
| P3-3 | Identity projection | `Registered`, `URIUpdated`, `MetadataSet`, `Transfer` → `agents` | `Transfer` clears `agent_wallet` in projection, matching on-chain behaviour |
| P3-4 | Reputation projection | `NewFeedback`, `FeedbackRevoked`, `ResponseAppended` | Revoked feedback excluded from scoring |
| P3-5 | Scoring engine | Fixed-point normalisation (`value / 10^decimals`), 90-day half-life decay, **curated** reviewer allow-list | Property test: score ∈ [0,100]; revoking the top review lowers the score |
| P3-6 | Sybil resistance | `getSummary` always client-filtered; curated reviewer roster; `minDistinctClients` necessary but **not sufficient** | **An attacker who registers, binds, and cross-reviews three of their own agents still does not reach T2**, because none are curated reviewers. The trivial case (ten reviews from one address) is also tested, but it is not the real threat — ERC-8004 registration is permissionless. (TH-4) |
| P3-7 | Validation projection | `ValidationRequest`/`ValidationResponse`; latest-response-wins per `tag` | Progressive finality (two responses, same `requestHash`) handled |
| P3-8 | Tier engine | T0–T3 tier predicates (monotonic) **plus** the separate `satm.mandate` authority axis, config-driven | Table-driven tests over the full predicate matrix; a **T2 client with a mandate** is authorized for asset tools while a **T3 provider without one** is not |
| P3-9 | Policy projector | Generate **tier-keyed** control-plane roles + node attenuation; **validate Datalog with SAM's own parser before push**. Roles are additive, so the tier∧authority conjunction is deliberately NOT projected as roles ([SPECIFICATION.md §10.1](SPECIFICATION.md)) | Malformed policy is rejected before reaching a node (TH-15); a mandated T1 agent does **not** gain custody access via any role |
| P3-10 | Trust API | `/v1/agents/{caid}`, `/v1/agents?skill&minTier`, `/v1/authorize` | Contract tests; OpenAPI published; **`self` derived from the authenticated sidecar channel, and a body-supplied `self` is ignored** (N-13) |
| P3-11 | Sidecar | Inbound + outbound checks; **call-attestation mint/verify**; `satm_*` MCP tools; evidence emission with counterparty co-signature | A T1 peer is denied a T2 service at the sidecar even if transport allowed it; an unattested or replayed request is denied |
| P3-12 | Registry-first discovery | Chain query → rank → resolve binding → intersect with SAM liveness | Offline T3 agent excluded; online T0 agent excluded |
| P3-13 | Degraded mode | Head-lag threshold; deny-on-degraded for mandate calls; **deny everything past `degraded.maxAge`**; `stale=true` recorded in evidence | Chaos test: kill RPC → mandate authorizations deny immediately; all authorizations deny after `maxAge` |

**Exit criteria:** the Treasury Agent discovers custodians via the registry, ranks them by
reputation, connects only to bound peers at the required tier, and a Sybil-inflated candidate
loses to a genuinely well-reviewed one.

---

## 6. Phase 4 — Compliance Plane (Weeks 4–7, parallel with Phase 3)

### 6.1 Contract work

| ID | Task | Acceptance |
| --- | --- | --- |
| P4-1 | `IAgentMandate` / `IComplianceProvider` interfaces, vendored **verbatim** from the EIP | ERC-165 IDs match; no signature drift |
| P4-2 | `ComplianceProvider` | Role-gated grant/revoke; `checkPrincipal` returns the full triple; expiry → `KYC_EXPIRED` |
| P4-3 | `AgentMandate` | All 13 rules in [SPECIFICATION.md §7.2](SPECIFICATION.md), incl. the compliance-provider allow-list, `getMandate`, `canExecuteStrict`, and the **immutable agent-identity pin** (§7.2b) — all SATM **extensions**, tested separately from conformance |
| P4-3a | **Agent identity pinning** | `declareAgentIdentity` write-once per wallet, registry allow-listed, wallet-proven; `grantMandate` requires it; `recordExecution` requires `isAgentIdentityLive` | **A wallet whose agent was transferred cannot regain authority by registering a fresh `agentId`** (TH-5c); re-pinning reverts |
| P4-4 | EIP-712 lifecycle ops | Domain `("RAMS","1",chainId,address(this))`; per-principal nonces; deadline enforcement; ERC-1271 |
| P4-5 | `TreasuryNote` | **Transfer-restricted**: `transfer`/`approve`/`transferFrom` revert (§7.3.0). `agentSubscribe`/`agentRedeem` authenticate the agent via `msg.sender == getAgentWallet(agentId)` **and** verify the immutable identity pin matches that `agentId`; execution-time `checkPrincipal` + provider allow-list re-check | Spoofed agent context reverts (TH-5a); transferred agent's old wallet reverts (TH-5); fresh-`agentId` substitution reverts (TH-5c); **an allowance-based `transferFrom` reverts** (TH-5d); expired KYC reverts (TH-6a) |
| P4-6 | `EquityNote` | No mandate → `canExecute` false on the `asset != m.asset` branch |
| P4-7 | `ReplayValidator` | Implements the validator side of ERC-8004 validation |
| P4-8 | Deployment scripts | Assert admin ≠ enforcer at deploy time; assert the asset holds `RECORDER_ROLE`; seed the compliance-provider allow-list |

### 6.2 ERC-8226 conformance suite

**One test per MUST clause**, enumerated in
[docs/RESEARCH-NOTES.md §3.4](docs/RESEARCH-NOTES.md):

| # | Clause | Test |
| --- | --- | --- |
| C-1 | One active mandate per `(agent, principal)` | Second `grantMandate` reverts |
| C-2 | `complianceProvider != address(0)` | Zero address reverts |
| C-3 | Ineligible principal | `checkPrincipal → false` ⟹ grant reverts |
| C-4 | Actions cleared then set at grant | Prior action disabled after re-grant; one `ActionEnabled` per action |
| C-5 | `extendMandate` monotonic | `newValidUntil <= validUntil` reverts |
| C-6 | `cumulativeUsed` survives extension | Extend does not reset usage |
| C-7 | `canExecute` branch coverage | Eight tests, one per early-return branch |
| C-8 | `recordExecution` caller restriction | Arbitrary caller reverts; asset/principal/recorder succeed |
| C-9 | `recordExecution` re-checks | Revoked/expired/frozen/wrong-action all revert |
| C-10 | Cap enforcement | Per-tx and cumulative overflow both revert **when `recordExecution` is called directly by an authorized recorder** — this is the only way to exercise the registry's own cap check, because the asset's `canExecute` guard fires first (see N-5) |
| C-11 | `type(uint256).max` = unlimited | No cap applied |
| C-12 | Freeze restricted; enforcer recorded | Non-enforcer reverts; event carries enforcer |
| C-13 | Admin ≠ enforcer | Invariant: no address holds both |
| C-14 | Operator rights | Operator may revoke/extend, not grant |
| C-15 | Signature replay | Reused nonce reverts; expired deadline reverts |
| C-16 | ERC-165 | `supportsInterface` true for both interfaces |

SATM's **additions** to ERC-8226 live in a separate `extensions/` file, so conformance and
extension results are reported independently and a future change to the draft does not blur the
two:

| # | Extension | Test |
| --- | --- | --- |
| X-1 | Compliance-provider allow-list (§7.2 rule 11) | `grantMandate` with a non-allow-listed provider reverts; **de-allow-listing a provider blocks execution**, not just future grants |
| X-2 | `getMandate` + `canExecuteStrict` views (§7.2 rule 12) | Return the data the asset needs; `canExecuteStrict` is false where `canExecute` is true after a transfer |
| X-3 | Execution-time eligibility (§7.3.1) | Principal revoked after grant ⟹ `agentSubscribe` reverts **although `canExecute` is still true** |
| X-4 | Agent authentication (§7.3.1) | `agentSubscribe` from a caller that is not the current `getAgentWallet(agentId)` reverts |
| X-5 | **Immutable identity pin** (§7.2b) | `declareAgentIdentity` twice reverts; a wallet pinned to a transferred agent is permanently inert; registering a fresh `agentId` for that wallet does not restore authority |
| X-6 | **Transfer restriction** (§7.3.0) | `approve` + `transferFrom` by an agent wallet holding an allowance reverts; `holderTransfer` and `forceTransfer` behave as specified |

Invariants (fuzz): monotonic `cumulativeUsed`; `cumulativeUsed ≤ maxCumulativeValue`; frozen
agents never execute; `canExecute == true` ⟹ `recordExecution` succeeds at the same block
**given an authorized recorder as caller** — without that qualifier the invariant is false, since
`canExecute` is a caller-agnostic view while `recordExecution` enforces a caller restriction.

### 6.3 Off-chain integration

| ID | Task | Acceptance |
| --- | --- | --- |
| P4-9 | Mandate projection in the indexer | `(agent, principal)` keying with `asset` column, mirroring on-chain storage |
| P4-10 | `satm_check_mandate` with **decoded reasons** | A `false` from `canExecute` resolves to exactly one of: not-found / wrong-asset / outside-window / revoked / action-disabled / frozen / per-tx-cap / cumulative-cap |
| P4-11 | `satm.mandate` label projection | `satm.mandate=active` attested independently of trust tier ([SPECIFICATION.md §5.2](SPECIFICATION.md)) |
| P4-12 | Never cache mandate decisions | `ttlSeconds == 0` whenever a mandate context is present; enforced by test |
| P4-13 | `satm-cli grant-mandate` / `revoke-mandate` / `freeze-agent` | Operator flows work end to end |

**Exit criteria:** the treasury subscription succeeds inside the mandate; the equities purchase
reverts on the wrong-asset branch; the over-cap subscription reverts at the asset's `canExecute`
guard **and** `recordExecution` independently rejects the same amount when called directly by an
authorized recorder; revoking the mandate stops the next action within one block; a principal
whose KYC is revoked after grant can no longer transact; a caller that is not the current
`agentWallet` cannot transact at all; and `satm_check_mandate` explains *why* in every failing
case.

---

## 7. Phase 5 — Settlement and Audit (Weeks 6–8)

| ID | Task | Acceptance |
| --- | --- | --- |
| P5-1 | `MockUSD` + `SettlementEscrow` | Full lifecycle: fund → deliver → release; refund after deadline |
| P5-2 | Payout resolves `getAgentWallet` **at release time** | A transferred agent (wallet cleared) cannot be paid |
| P5-3 | Escrow projection in the indexer | `JobSettled` linked to job and CAID |
| P5-4 | Feedback publication | Off-chain file to IPFS; `giveFeedback` with `feedbackHash = bytes32(0)` for IPFS, required hash for HTTPS |
| P5-5 | Client address correctness | Agent-as-client uses its `agentWallet` as `clientAddress`, per ERC-8004 |
| P5-6 | Validation request flow | Agent requests validation; Validator Agent re-executes and responds `100`/`0` |
| P5-7 | Evidence log | Hash-chained records; `argsHash` only, never raw arguments (TH-14) |
| P5-8 | Merkle batching + `AuditAnchor` | Root anchored on the L1 Anvil/Sepolia; `Anchored` event observed |
| P5-9 | `GET /v1/evidence/{id}/proof` | Inclusion proof verifies against the anchored root, independently of the broker |
| P5-10 | Anchor failure isolation | L1 outage does not block agent traffic; `anchor_lag_seconds` alerts |

**Exit criteria:** a full job produces payment, settlement-backed feedback, an independent
validation, and an L1-anchored evidence trail with a verifiable inclusion proof.

---

## 8. Phase 6 — Demo, Negative Controls, Hardening (Weeks 8–10)

| ID | Task | Acceptance |
| --- | --- | --- |
| P6-1 | Treasury Agent | Discovery → ranking → mandate check → subscribe → feedback |
| P6-2 | Custodian Agent | `mcp://custody` tools; inbound tier enforcement |
| P6-3 | Validator Agent | Deterministic re-execution; on-chain response |
| P6-4 | **Rogue Agent** | All eighteen attack scenarios below denied, each at a named layer |
| P6-5 | Scripted demo | `make demo` runs the full scenario with narrated output |
| P6-6 | Chaos tests | RPC outage, indexer lag, broker outage, reorg, IPFS outage |
| P6-7 | Observability | Metrics, tracing, dashboards per [SPECIFICATION.md §15](SPECIFICATION.md) |
| P6-8 | Testnet promotion | Base Sepolia (canonical registries) + Ethereum Sepolia anchor |
| P6-9 | Documentation | README, [docs/DEMO.md](docs/DEMO.md), ADRs, operator runbook |
| P6-10 | Security review pass | Threat model walkthrough; residual risks documented |

### 8.1 Negative controls (P6-4)

A trust prototype that only demonstrates the happy path proves nothing. Each of these MUST be
part of the scripted demo:

| # | Attack | Expected denial | Layer |
| --- | --- | --- | --- |
| N-1 | Unbound node attempts to join the mesh | Enrollment rejected after grace period | Broker |
| N-2 | Node claims `agentId 42` without the wallet key | Binding rejected at B9 | Broker |
| N-3 | Valid T1 agent calls a T2 custody service | Denied at node attenuation **and** sidecar | Mesh + sidecar |
| N-4 | Mandated agent attempts to buy equities | Reverts — `asset != m.asset` | On-chain (`canExecute`) |
| N-5 | Mandated agent exceeds cumulative cap | Reverts at the asset's `canExecute` guard; `recordExecution` independently rejects the same amount when called directly by an authorized recorder | On-chain (both layers, tested separately) |
| N-6 | Mandate revoked mid-session | Next action fails within one block | On-chain |
| N-7 | Agent NFT transferred to attacker | Old wallet's `agentSubscribe` reverts immediately; mesh access revoked within one reconcile interval | On-chain + broker |
| N-8 | Sybil: attacker registers, binds, and cross-reviews **three of their own agents** | No promotion to T2 — none are curated reviewers | Trust engine |
| N-9 | Binding replayed on a second mesh | Rejected at B2/B3 | Broker |
| N-10 | Chain RPC down, agent attempts asset action | Denied (fail-closed) | Degraded mode |
| N-11 | Binding names an attacker-deployed registry | Rejected at B2a before any chain read | Broker |
| N-12 | Call attestation replayed at a different callee, or with mutated arguments | Rejected on target / `argsHash` / freshness mismatch | Sidecar |
| N-13 | Caller spoofs `self` in `/v1/authorize` | Body `self` ignored; identity taken from the authenticated channel | Broker |
| N-14 | Operator removes the `SAM` service entry; old PeerID keeps calling | Revoked within one reconcile interval | Broker |
| N-15 | Principal's KYC revoked after the mandate was granted | `agentSubscribe` reverts although `canExecute` is still true | On-chain (asset) |
| N-16 | Transferred agent's old wallet registers a **fresh `agentId`** pointing at itself and reuses the stale mandate | Reverts — the wallet's identity pin is immutably the old `agentId`, which is no longer live | On-chain (`AgentMandate`) |
| N-17 | Agent wallet holds an ERC-20 allowance and calls `transferFrom` directly, bypassing the agent context | Reverts — `TreasuryNote` has no open transfer paths | On-chain (asset) |
| N-18 | Read-tool attestation presented to an asset-moving tool | Rejected — signed `service`/`tool` must equal the actual request (V3) | Sidecar |

---

## 9. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- |
| **R-1** | SAM's enrollment approval cannot attest labels (OI-1) | Medium | Medium | Fallback declare-then-validate path already specified; S-1 resolves in week 1 | Mesh |
| **R-2** | Node attenuation does not evaluate caller labels as read (OI-2) | Low | High | S-2 verifies in week 1; sidecar already carries inbound enforcement | Mesh |
| **R-3** | SAM upstream churn breaks integration (`v1alpha1`, "not officially supported") | **High** | Medium | Pin a commit/release; S-2 regression test in CI catches breakage same-day; integration confined to `services/broker/samclient` | Mesh |
| **R-4** | ERC-8226 changes before Final | Medium | Medium | Interfaces vendored verbatim; one conformance test per MUST clause localises the diff | Chain |
| **R-5** | ERC-8004 Validation Registry is revised with the TEE community | **High** | Low | `ValidationPort` abstraction; validation is Phase 4/5 and not on the critical path | Chain |
| **R-6** | Reviewer allow-list cold start, and permissionless registration makes "any bound agent" a near-free identity (OI-6) | High | **Medium** | v0.1 uses an operator-curated roster, not "any bound agent"; settlement-weighted reviewers designed as the Phase 5 stretch; N-8 tests the strong attacker, not the trivial one | Chain |
| **R-7** | Go 1.25 toolchain availability in CI | Medium | Low | Pin via `.tool-versions`; prefer released SAM containers over building from source | Mesh |
| **R-8** | Broker is a single trusted admission authority, and can omit or fabricate evidence before anchoring (TH-7, OI-11) | Certain | Medium | Scope its credential to the control plane only; counterparty co-signed receipts make omission detectable; anchoring gives post-hoc immutability, not prevention; documented residual risk | All |
| **R-9** | Scope creep into production compliance (real KYC) | Medium | High | `ComplianceProvider` is explicitly a stub with an adapter seam; out of scope per §1.3 | All |
| **R-10** | IPFS availability affects binding verification | Medium | Low | Negative caching, `staleRevokeAfter` grace, HTTPS fallback endpoint permitted | Mesh |
| **R-11** | Demo depends on public testnet liveness | Medium | Medium | Local Anvil devnet is the primary demo target; testnet is a promotion, not a dependency | Demo |

---

## 10. Testing Strategy

| Level | Scope | Tooling | Gate |
| --- | --- | --- | --- |
| Unit | Signature verification, canonicalisation, scoring, tier predicates, URI parsing | `go test`, `forge test`, `pytest` | Every PR |
| Property/fuzz | Score bounds, Datalog generation, `sam://` parser, JSON validator | `go-fuzz`/native fuzzing, `forge fuzz` | Every PR |
| Invariant | RAMS caps, freeze, role separation | `forge invariant` | Every PR |
| Conformance | One test per ERC-8226 MUST clause; ERC-8004 behaviours | `forge test` | Every PR |
| Integration | Broker ↔ control plane; indexer ↔ chain; sidecar ↔ node | Testcontainers + Anvil | Every PR |
| E2E | Full scenario incl. all ten negative controls | `make test-e2e` on the compose devnet | Merge to main |
| Chaos | RPC outage, reorg, broker outage, indexer lag, IPFS outage | `tests/chaos/` | Nightly |
| Regression | **S-2 attenuation behaviour** | `tests/e2e/` | Every PR — this is our upstream-breakage tripwire |

**Coverage targets:** ≥85% on `services/broker` binding and authorization paths; 100% branch
coverage on `canExecute` and `recordExecution`; every threat in
[SPECIFICATION.md §13](SPECIFICATION.md) mapped to at least one test.

---

## 11. Milestones

| Milestone | Week | Definition of done | Demonstrates |
| --- | --- | --- | --- |
| **M0 — Reproducible env** | 1 | `make devnet-up` yields two SAM nodes + two chains + registries | — |
| **M1 — Unknowns retired** | 2 | S-1…S-4 closed; OI-1/OI-2 resolved in the spec | — |
| **M2 — Binding works** | 4 | Bound node admitted; unbound rejected; NFT transfer revokes access | Portable identity (A3) |
| **M3 — Trust gates traffic** | 6 | Registry-first discovery; reputation ranking; tier-gated calls; Sybil resisted | A1, A2, A4 |
| **M4 — Authority enforced** | 7 | Treasury allowed; equities denied; cap denied; revocation immediate | A5, A8 |
| **M5 — Value and evidence** | 8 | Escrow settles; feedback carries payment proof; L1 anchor + proof | A6, A7 |
| **M6 — Demo complete** | 10 | Scripted scenario incl. 10 negative controls; chaos green; testnet run | A1–A9 |

### 11.1 Critical path

```
P0-3/P0-4 ──▶ S-1 ──▶ P2-9 ──▶ P2-10 ──▶ P2-12 ──▶ P3-9 ──▶ P3-11 ──▶ P6-5
    devnet    approval  gate     labels   reconcile  policy   sidecar   demo
                 │
                 └── S-2 (attenuation) ──▶ P3-9
```

Contract work (Phase 4) is **off** the critical path and can start as soon as P0-5 lands, which
is why it is scheduled in parallel from week 4.

---

## 12. Definition of Done for the Prototype

The prototype is complete when **all nine acceptance criteria** in
[SPECIFICATION.md §16.1](SPECIFICATION.md) pass in CI on the local devnet **and** on testnet, and
`make demo` runs the full narrated scenario — happy path plus all ten negative controls — without
manual intervention.

The narrative the demo must support, end to end:

> A corporate treasury agent, with no prior relationship to any counterparty, discovers custodians
> through an on-chain registry, ranks them by portable reputation that resists Sybil inflation,
> connects over an authenticated peer-to-peer mesh that admits only cryptographically bound
> agents, proves its own delegated authority under a machine-verifiable mandate, executes a
> regulated asset purchase that the asset contract itself validates atomically, settles payment
> in stablecoin, publishes reputation backed by proof of payment, and leaves an audit trail
> anchored to Ethereum L1 that a regulator can verify without trusting any operator.
>
> And when it tries to buy equities it is not authorized to hold, the transaction reverts.

---

## 13. Beyond the Prototype

Not committed work — the natural next questions, recorded so the prototype is built in a
direction that does not foreclose them.

| Theme | Direction |
| --- | --- |
| Decentralising admission | Replace the single broker with a quorum of attesters, or move binding verification on-chain so the mesh reads it directly |
| Enterprise identity | Bridge enterprise identity providers (Entra ID, Okta) and W3C Verifiable Credentials into `ComplianceProvider` and into the OIDC claims the control plane consumes |
| Reputation markets | Auditor networks, insurance pools, and staked reviewer reputation — all anticipated by ERC-8004 |
| Real validation | zkML and TEE attestation once ERC-8004's validation section stabilises |
| Cross-chain identity | Agents registered on multiple chains, with the mesh resolving across them |
| Privacy | Selective disclosure of mandate terms; today `canExecute` leaks scope to any observer |
| Upstreaming | Offer the binding pattern to SAM and the `sam://` service-entry convention to the ERC-8004 community |
