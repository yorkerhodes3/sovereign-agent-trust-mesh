# satm-broker

The Trust Broker: the service that verifies Agent Mesh Bindings, gates SAM
enrollment on on-chain verification, and projects on-chain trust into mesh
policy.

Phase 2 delivers the **binding verifier** — the core novel mechanism — together
with the three ports it runs on and a `satm-broker` binary that composes them.
Enrollment gating, policy projection and the Trust API follow in the rest of
Phase 2/3.

## What is implemented and proven

```
cmd/satm-broker/   HTTP service + reconciliation loop
internal/binding/
  document.go      canonical document + normative field encodings
  peerproof.go     checks B4, B5   libp2p host-key proof
  eip712.go        check  B9       EIP-712 MeshBinding digest
  ecdsa.go                          secp256k1 recovery, low-s enforced
  registration.go  checks B11-B13  ERC-8004 registration file + sam:// grammar
  verifier.go      checks B1-B15   the ordered pipeline
  revalidate.go                     post-admission re-checks for the reconciler
  reasons.go                        stable reason codes
internal/fetch/    RegistrationFetcher, SSRF-hardened  (TH-8, TH-9)
internal/chainrpc/ ChainClient over JSON-RPC + hand-rolled ABI  (TH-11)
internal/reconcile/ revocation loop  (TH-5, TH-16)
internal/store/    in-memory NonceStore + shared conformance suite
internal/pgstore/  PostgreSQL NonceStore
internal/config/   satm-broker.yaml loading and validation

../internal/canonicaljson/  RFC 8785 JCS, shared with the sidecar
```

`go test ./...` → **all pass**; coverage 84–96% in every package with logic.

The suite follows [SPECIFICATION.md §4.6](../../SPECIFICATION.md): **one test per
check, each proving denial in isolation**, so a failing test name points straight
at the numbered check it defends.

| Test | Defends |
| --- | --- |
| `B2a_RejectsAttackerDeployedRegistry` | **TH-3a / N-11.** The attacker deploys their own ERC-8004-shaped registry, mints themselves `agentId 42` with a wallet they control, publishes a matching file, and signs both proofs correctly. The submission is *internally consistent* — every other check passes. Only the allow-list stops it. |
| `B2a_DomainIsDerivedFromAllowlistNotDocument` | The second half of that defence: the EIP-712 domain is **ours**, so a signature made against a different domain does not verify. |
| `B15_ConcurrentSubmissionsCommitExactlyOnce` | The check/consume split. Eight goroutines pass B3 together; exactly one survives B15. |
| `TH17_UnsignedSubmissionCannotBurnANonce` | A caller who cannot sign must not be able to consume a nonce they do not own. |
| `B9_RejectsSignatureFromWrongWallet` | **TH-1.** An impostor controls the PeerID but not the `agentWallet`. |
| `B7_RejectsClearedAgentWallet` | **TH-5.** ERC-8004 zeroes `agentWallet` on transfer, so a sold agent's binding fails with no SATM-specific bookkeeping. |
| `B9a_RejectsWalletAlreadyBoundToAnotherAgent` | **TH-5b.** Two agents sharing a wallet would silently share ERC-8226 mandates and caps. |
| `RecoverAddress_RejectsHighS` | Signature malleability: `(r, n-s)` is equally valid, so accepting both gives one authorisation two encodings. |
| `RebindingRevokesThePriorBinding` | **A3.** Key rotation keeps the `agentId` and retires the old PeerID atomically. |
| `BlockedIP` / `FetchRefusesRedirectToLoopback` | **TH-8.** The `agentURI` is attacker-chosen, so every fetch is attacker-directed. Includes `169.254.169.254` (cloud metadata) and IPv4-mapped IPv6 loopback, the classic bypass. |
| `CheckJSONShapeDepth` | **TH-9.** 40 KB of `[[[[...` is under any byte cap yet exhausts the stack during decoding. |
| `QuorumRefusesOnDisagreement` | **TH-11.** A single lying RPC provider could otherwise forge the chain state an entire binding rests on. |
| `LiveReconcileRevokesTransferredAgent` | **TH-5, on a live chain.** The agent NFT is transferred with `cast`, and the next sweep revokes the binding. This is PLAN exit criterion 3. |
| `SweepDoesNotRevokeOnInfrastructureFailure` | The inverse, and just as important: an RPC outage must revoke **nothing**, or one bad afternoon at a provider takes down the whole mesh. |

## Revocation

A binding is not a permanent fact. Three things can invalidate one after
admission, none of which produce any signal at the broker: the agent NFT is sold
(TH-5), the registration file is edited to drop the `SAM` service entry (TH-16),
or the agent is marked inactive.

`internal/reconcile` sweeps active bindings and re-runs the post-admission
checks. Two design points:

**It reuses the same check implementations as admission.** A second
implementation would drift, and a reconciler more permissive than the admission
path is worse than none — it would report everything healthy while the invariant
it protects had already broken.

**"Could not check" and "checked and failed" stay distinct.** Only a genuine
verdict revokes. RPC outages, unreachable registration hosts, and *unclassified*
errors all leave bindings in place and log loudly. Note that `binding.ReasonOf`
maps unclassified errors to `ReasonMalformed`, so it deliberately is **not** used
to make this decision.

Revocation writes to the store first — it is authoritative — and then tells the
control plane, so a control-plane outage cannot leave a sold agent trusted by
the broker. The nonce is never released: a revoked binding's document is still
validly signed, so recycling its nonce would let the agent re-admit itself with
the very document just revoked.

## Tests that need real infrastructure

Two build-tagged suites run against live services. Both execute in CI
([.github/workflows/services.yml](../../.github/workflows/services.yml)).

```bash
# Live chain: needs anvil + the registries deployed (see contracts/)
go test -tags integration ./broker/internal/chainrpc/ ./broker/cmd/satm-broker/

# Postgres NonceStore conformance
SATM_POSTGRES_DSN=... go test -tags postgres ./broker/internal/pgstore/
```

These exist because the stubbed tests genuinely cannot catch certain classes of
bug:

- **`getAgentWallet(uint256)` has no publicly documented selector** to pin
  against, unlike `ownerOf` and `tokenURI`. A wrong keccak derivation would look
  perfectly healthy against a scripted JSON-RPC server and fail only in
  production. Only a call to real bytecode settles it.
- **The TH-5 clear-on-transfer property** is asserted at the Solidity level in
  `contracts/`, but that says nothing about whether the *broker* observes it. The
  live test checks it through the broker's own code path.
- **The Postgres store's atomicity** lives in the database, not in Go. The shared
  conformance suite in `internal/store/storetest` is run against both stores, so
  "the Postgres store behaves like the in-memory store" is checked rather than
  assumed — the 32-way concurrent-commit case in particular.

## Four decisions worth knowing

**PeerID derivation is delegated, not reimplemented.** The obvious
`multihash(raw key bytes)` is wrong in the dangerous direction — it accepts keys
that do not produce the claimed PeerID. libp2p uses `multihash(protobuf(pubkey))`
with the *identity* hash for keys ≤ 42 bytes, so `peer.IDFromPublicKey` is called
directly. Host keys are restricted to Ed25519 so that path always applies.

**JCS is hand-rolled.** `encoding/json` is close to RFC 8785 but not equal: it
HTML-escapes `<`, `>`, `&`, and it sorts map keys by UTF-8 bytes rather than
UTF-16 code units. Since the two signers may not both be Go — an operator might
sign in Python or TypeScript — a one-byte disagreement means a valid signature
fails to verify, or an attacker finds an input where the two disagree usefully.

Non-integer JSON numbers are **rejected outright** rather than approximated.
Binding documents carry every numeric value as a decimal string precisely so no
float enters the signing path; if a future schema adds a real number, this must
grow a full ECMAScript `Number::toString` rather than be loosened.

**SSRF blocking happens at dial time, not at parse time.** Validating the
hostname up front is insufficient: a name can resolve to a public address on the
first lookup and to `127.0.0.1` on the second. The check therefore lives in the
transport's `DialContext` hook, where the address actually being connected to is
visible.

**Quorum disagreement is an error, not a vote.** When RPC providers return
different answers the client refuses to proceed rather than taking a majority or
the first response. For reads that gate admission, "my providers disagree about
who owns this agent" is exactly the situation in which continuing is unsafe.

## Not yet implemented

| Piece | Where it stands |
| --- | --- |
| Enrollment gate (`/admin/enrollments` polling) | Not blocked; admin API shape documented in [BACKLOG.md §3](../../BACKLOG.md) |
| Label projection into Biscuit tokens | Blocked on the enrollment gate |
| `satm-cli bind` | Not blocked; every primitive it needs is exported and tested |
| Mesh revocation propagation (`/admin/revoke`) | Reconciler revokes locally; the control-plane call is a `NoopMeshRevoker` that warns loudly |
| Trust tiers, policy projection | Phase 3 |

Call attestation (V1–V8) now lives in
[services/sidecar](../sidecar/README.md).

## Running

```bash
cd services
go build ./...
go vet ./...
go test ./...

# Serve, against a devnet configured in broker/satm-broker.yaml
go run ./broker/cmd/satm-broker -config broker/satm-broker.yaml
curl http://127.0.0.1:8081/healthz
```

**The race detector needs cgo**, which was unavailable on the Windows machine
this was written on. `-race` therefore runs in CI rather than locally — which is
where a concurrency check belongs anyway, but it does mean the B15 race test was
first exercised under `-race` on the runner, not here.
