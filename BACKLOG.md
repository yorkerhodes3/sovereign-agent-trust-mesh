# BACKLOG

What is built, what is not, and precisely what each remaining item needs.

The organising principle: **an item is only "done" when something automated
proves it.** Items below are marked with how they were verified, or with the
specific reason they cannot be yet.

Last updated 2026-08-23. Companion to [PLAN.md](PLAN.md), which holds the
phase structure and the full risk register.

---

## 1. Status at a glance

| Phase | State |
| --- | --- |
| 0 — Foundations (contracts, vendored registries) | ✅ complete, 18/18 contract tests, live devnet deploy |
| 1 — De-risking spikes S-1…S-5 | ✅ complete, all five closed against a real SAM mesh |
| 2 — Identity plane and Agent Mesh Binding | 🔨 **11 of 14 tasks done**; the 3 remaining all need live SAM integration |
| 3 — Trust plane | ⬜ not started |
| 4 — Compliance plane (ERC-8226 / RAMS) | ⬜ not started |
| 5 — Settlement and audit | ⬜ not started |
| 6 — Demo, negative controls, hardening | ⬜ not started |

Every Go package is built, vetted and tested in CI on every push, including
`-race`, a live-chain job against Anvil, and a PostgreSQL service container.

---

## 2. Phase 2 — what is done

| ID | Task | Evidence |
| --- | --- | --- |
| P2-1 | Binding document + RFC 8785 canonicalisation | Unit tests incl. the UTF-16 vs UTF-8 key-ordering divergence and rejection of non-integer numbers |
| P2-2 | PeerID proof (B4, B5) | Delegates to `peer.IDFromPublicKey`; tests cover mismatched key, wrong PeerID, non-Ed25519 |
| P2-2a | Registry allow-list (B2a) | Test constructs an internally consistent binding against an attacker-deployed registry; only the allow-list stops it |
| P2-3 | Wallet proof (B9, EOA + ERC-1271) | Tests with EOA, contract wallet, wrong signer, and a signature valid under a different domain |
| P2-4 | SSRF-hardened resolver | Private-range blocking asserted at dial time; redirect-to-loopback, oversized body, deep JSON, bad scheme all refused |
| P2-5 | Registration file + `sam://` grammar (B11–B13) | Unit tests over the parser and the tuple comparison |
| P2-6 | Full `verify_binding` (B1–B15) | One test per check proving denial in isolation; 32-way concurrency test; TH-17 nonce-burn test |
| P2-7 | Trust store | In-memory + PostgreSQL, both passing one shared conformance suite; the Postgres run is a CI service container under `-race` |
| P2-8 | `POST /v1/bindings` | 9 end-to-end tests against ERC-8004 registries deployed on Anvil |
| P2-12 | Reconciliation loop | **Live test: agent NFT transferred on-chain → binding revoked with `binding.agent_wallet_unset`.** Negative controls: healthy bindings survive repeated sweeps; a dead RPC endpoint revokes nothing |
| P2-13 | Call attestation (V1–V8) | 41 tests, 87.3% coverage: one per check, plus replay at a different callee, read-tool→asset-tool escalation, mutated args, superseded binding, TTL replay, 32-way concurrent replay |
| P2-14 | Split authorize schemas | Sidecar HTTP tests assert inbound refuses `peer.peerId`, outbound refuses `peer.attestation`, and a body-supplied `self` is rejected outright |

**P2-12 is PLAN.md exit criterion 3** — on-chain ownership change propagating
into live access control — and it is the most convincing thing in the repo
today.

---

## 3. Phase 2 — what remains

Three tasks. All three need a running SAM control plane, which is why they are
grouped here rather than scattered.

### P2-9 — Enrollment gate

Poll `/admin/enrollments`, match a pending PeerID against a committed binding,
approve or reject, and reject anything still unbound after a grace period.

**Not blocked. Ready to implement.** The admin API was inspected directly at
upstream `674af93`:

| Endpoint | Method | Encoding |
| --- | --- | --- |
| `/admin/enrollments` | GET | **JSON** |
| `/admin/enrollments/{id}/approve` | POST | empty body (confirmed in spike S-1) |
| `/admin/enrollments/{id}/reject` | POST | empty body |
| `/admin/revoke` | POST | **protobuf** `api.TokenRevokeRequest` |

What is needed:

1. An admin HTTP client. Auth is OIDC — `checkAdminAuth` calls
   `authenticateUser` and requires `role == "admin"`, which is why
   [tools/spike/oidc_stub.py](tools/spike/oidc_stub.py) exists.
2. A poll loop with a configurable grace period.
3. An integration test driving a real `sam-control-plane`.

**Caveat, and it is a real one.** The broker side of this is fully testable,
but the *complete* flow — node submits, broker approves, node joins — is
blocked by [google/sam#297](https://github.com/google/sam/issues/297)
(reported by this project, still open). `sam-node` POSTs to `/enroll/status`
while the server accepts only GET, so a node can never learn it was approved.
The enrollment request is still *created* and the broker can still approve it,
so P2-9 can be built and tested; only the end-to-end demo needs the upstream
fix or a local patch.

### P2-10 — Label projection

Project `erc8004.agent_id` and trust tier into the Biscuit the control plane
mints at approval.

**Blocked on P2-9**, not on anything upstream. Spike S-1 established the
mechanism: labels are declared by the node via `sam-node run --labels` (the
flag is on `run`, **not** `join`) and attested by the admin at approval time.
The specification's original "primary path", where the broker supplies labels
in the approve call, **does not exist** — §6.1.3 was corrected accordingly.

Verification once built: decode the minted Biscuit and assert the label is
present. `satm-biscuit-dump` already exists in the spike toolchain for this.

### P2-11 — `satm-cli bind`

One command that takes a fresh node from nothing to a committed binding: read
the libp2p host key, generate a sidecar keypair, build the document, sign it
twice, submit it.

**Not blocked.** Every primitive it needs is already exported and tested —
`binding.NewDocument`, `PeerSigningDigest`, `MeshBindingDigest`,
`CanonicalJSON`. The end-to-end tests already perform this sequence
programmatically; the CLI is a thin wrapper over the same calls.

The only real design question is key handling: the wallet signature needs the
ERC-8004 `agentWallet` key, and shelling out to a hardware wallet or an
external signer is preferable to reading a private key from disk.

---

## 4. Known gaps in what is already built

Honest limitations of shipped code, as distinct from unstarted work.

| Gap | Impact | What would close it |
| --- | --- | --- |
| **Outbound authorization is unimplemented** | `satm-sidecar` returns `501 sidecar.outbound_not_implemented`. It fails closed and a test asserts it never returns allow. | Needs a broker `peerId → binding` resolution endpoint plus tier lookup, i.e. the Phase 3 trust plane. |
| **Mesh revocation is not propagated** | The reconciler revokes locally, which is authoritative for the broker, but the peer keeps its Biscuit until expiry. `NoopMeshRevoker` logs a warning rather than failing silently. | Implement `MeshRevoker` against `/admin/revoke`. Note this is **protobuf**, so it needs `github.com/google/sam/api` — the first real dependency on SAM's Go module. |
| **No trust tiers yet** | Attestation proves *who* is calling. Nothing yet decides whether that caller is *allowed*. | Phase 3. |
| **No mandate evaluation** | Asset-moving tools have no `canExecute` check. | Phase 4 (ERC-8226 / RAMS). |
| **Sidecar is not an MCP proxy** | It exposes `/v1/authorize` over HTTP but does not yet sit in the MCP path. | Wrap the authorize call in an MCP server that forwards to the real service. |
| **`deploy/compose/docker-compose.yml` has never been executed** | No Docker in the development environment. Corrected from spike findings but labelled unverified in-file. | Run it once on a machine with Docker. |
| **Single-broker assumption in the default build** | `cmd/satm-broker` wires the in-memory store. Two replicas would each accept the same nonce once. | Wire `internal/pgstore` behind config. The store already passes the same conformance suite, including 32-way concurrency in CI. |
| **Trust API cache weakens V6 slightly** | `trustapi` caches bindings for 5s by default, so a revocation can take up to that long to be observed by a sidecar. | Deliberate and documented; `Invalidate` exists. Set `CacheTTL: 0` for strict freshness. |

---

## 5. Upstream dependency

**[google/sam#297](https://github.com/google/sam/issues/297)** — bootstrap
enrollment cannot complete. Filed by this project after re-verifying against
upstream HEAD `674af93`. Still open, no upstream response.

`sam-node` and `sam-router` POST to `/enroll/status`; `HandleEnrollStatus`
accepts only GET with a `peer_id` query parameter, so the request 405s forever.

Impact on SATM: the P2-9 **demo** is blocked; P2-9 **implementation** is not.
Per [ADR-0001](docs/adr/0001-integrate-via-control-plane-not-fork.md) SATM does
not fork SAM, so the one-line fix is applied only to the local scratch clone
used for spikes.

If it remains unfixed, options in preference order:

1. Wait, and demo the broker-side gate against the admin API only.
2. Carry a documented local patch in the demo environment, clearly labelled as
   working around an upstream defect.
3. Vendor a patched `sam-node` for the demo, which would need ADR-0001 revised.

---

## 6. Environment constraints

Things that limit what can be verified locally rather than in CI.

| Constraint | Consequence | Mitigation |
| --- | --- | --- |
| **No cgo locally** | `-race` cannot run on the development machine | CI runs every test under `-race` on Linux |
| **No Docker** | Compose stack unverified | CI service containers cover Postgres; Anvil runs natively |
| **No Postgres locally** | `pgstore` cannot be exercised locally | CI service container runs the shared conformance suite |
| **Go is not on PATH by default** | Toolchain lives at `%LOCALAPPDATA%\satm-toolchain\go` | Prepend it in each shell |
| **`make` unavailable on Windows** | — | [make.ps1](make.ps1) mirrors the Makefile |

---

## 7. Suggested order of work

1. **`MeshRevoker` against `/admin/revoke`** — smallest item that closes a real
   gap in shipped behaviour, and completes the revocation story end to end.
2. **P2-9 enrollment gate** — unblocks P2-10 and is the last piece of the
   admission path.
3. **P2-10 label projection** — makes on-chain identity visible to SAM's own
   Datalog, which is what spike S-2 proved is enforced at the transport layer.
4. **P2-11 `satm-cli bind`** — turns the prototype into something another person
   can actually run.
5. **Phase 3 trust plane** — unblocks outbound authorization and per-service
   minimum tiers.

Items 1–4 are all independent of the upstream defect except for the final
end-to-end demo of item 2.
