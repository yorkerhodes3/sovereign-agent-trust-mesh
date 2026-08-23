# satm-broker

The Trust Broker: the service that verifies Agent Mesh Bindings, gates SAM
enrollment on on-chain verification, and projects on-chain trust into mesh
policy.

Phase 2 delivers the **binding verifier** — the core novel mechanism. Enrollment
gating, policy projection and the Trust API follow in the rest of Phase 2/3.

## What is implemented and proven

```
internal/binding/
  document.go      canonical document + normative field encodings
  canonical.go     RFC 8785 JCS serialisation
  peerproof.go     checks B4, B5   libp2p host-key proof
  eip712.go        check  B9       EIP-712 MeshBinding digest
  ecdsa.go                          secp256k1 recovery, low-s enforced
  registration.go  checks B11-B13  ERC-8004 registration file + sam:// grammar
  verifier.go      checks B1-B15   the ordered pipeline
  reasons.go                        stable reason codes
```

`go test ./...` → **31/31 pass**, 73% statement coverage.

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

## Three decisions worth knowing

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

**Ports, not concrete clients.** `ChainClient`, `RegistrationFetcher` and
`NonceStore` are interfaces, so the whole B1–B15 pipeline is testable with no RPC
endpoint, no IPFS and no database. The fakes are simple in-memory
implementations, not mocks with call-order expectations — the tests assert on
*verifier* behaviour, and coupling them to internals would make legitimate
refactors look like failures.

## Not yet implemented

| Piece | Phase |
| --- | --- |
| `ChainClient` against a real RPC endpoint | 2 (next) |
| SSRF-hardened `RegistrationFetcher` | 2 (next) |
| Postgres `NonceStore` | 2 (next) |
| Enrollment gate (`/admin/enrollments` polling) | 2 |
| Trust API, policy projection, reconciliation | 2–3 |

The interfaces are defined and exercised, so these are substitutions rather than
redesigns.

## Running

```bash
cd services/broker
go build ./...
go vet ./...
go test ./...
```

**The race detector needs cgo**, which was unavailable on the Windows machine
this was written on. `-race` therefore runs in CI
([.github/workflows/broker.yml](../../.github/workflows/broker.yml)) rather than
locally — which is where a concurrency check belongs anyway, but it does mean the
B15 race test was first exercised under `-race` on the runner, not here.
