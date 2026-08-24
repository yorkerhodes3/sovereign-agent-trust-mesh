# satm-sidecar

The Trust Sidecar. Runs next to an agent as a transparent MCP proxy and answers
the authorization questions the mesh layer cannot.

```
Agent  ──MCP──▶  satm-sidecar  ──MCP──▶  sam-node  ──libp2p──▶  remote sam-node
```

SAM's node-level Datalog can express *"is this caller bound and tiered?"*. It
cannot express *"is this specific transfer within this mandate's remaining
cumulative cap right now?"*. That gap is why this exists.

## Why the Call Attestation is not optional

This is the part worth understanding before reading any code.

Spike S-1 through S-5 tested SAM empirically rather than trusting its docs.
**S-5 found that SAM does not pass the authenticated caller identity to a
locally-spawned service.** `internal/node/gate.go` describes the path as a
*"dumb-pipe proxy"* and calls `mcpSvc.HandleStreamPassThrough(s)`, forwarding
the raw stream. The request context carries the caller's PeerID but uses it only
to select the target service, then discards it. The spawned subprocess sees no
`SAM_*`, `PEER_*` or `CALLER_*` environment variables.

So if the sidecar simply trusted a `peerId` field in the request body, **any
caller could name someone else's CAID** and inherit their trust tier and
spending authority. That is threat TH-7a.

The Call Attestation is therefore the *only* mechanism by which an inbound
sidecar learns who called it — necessary, not defence in depth.

## What is implemented

```
cmd/satm-sidecar/     HTTP service: POST /v1/authorize
internal/trustapi/    broker Trust API client (binding resolution for V5/V6)

../internal/attest/   the attestation itself, shared with the broker:
  document.go           signed payload, normative encodings, RFC 8785 + SHA-256
  verifier.go           checks V1..V8, ordered, first-failure denial
  noncestore.go         atomic nonce consumption (V8)
  reasons.go            stable reason codes
```

`go test ./...` → **41 attestation tests, 87.3% coverage**, plus HTTP-level
tests for the sidecar itself.

| Check | What it prevents | Test |
| --- | --- | --- |
| V1 | Cross-mesh replay | `V1_RejectsWrongMesh` |
| V2 | Replay at a **different callee**, or after this agent re-bound | `V2_RejectsReplayAtDifferentCallee` |
| V3 | Escalating a cheap read-tool attestation into an asset-moving call | `V3_RejectsToolEscalation` |
| V4 | Body substitution under a genuine attestation | `V4_RejectsMutatedArguments` |
| V5 | Forgery by someone who knows every public field | `V5_RejectsForgedSignature` |
| V6 | Use of a revoked or superseded binding | `V6_RejectsSupersededCallerBinding` |
| V7 | Long-lived replay; self-issued long TTLs | `V7_RejectsExpiredAttestation`, `V7_RejectsOverlongTTL` |
| V8 | Concurrent replay | `V8_ConcurrentReplayAdmitsExactlyOne` |

## Four decisions worth knowing

**V6 is what makes the hot key revocable, with no revocation list.** The
caller's `bindingId` is inside the signature and must be their *current*
binding. Re-binding an agent — which the broker does atomically at check B15 —
invalidates every outstanding attestation signed under the old sidecar key. The
binding id doubles as a key epoch.

**V8 runs last, and that ordering is load-bearing.** Consuming a nonce is a side
effect. Doing it before the signature check would let an unauthenticated caller
burn nonces belonging to a binding it does not control — the attestation-layer
analogue of threat TH-17. A test asserts a failed verification consumes nothing
and that the legitimate holder can still use that nonce afterwards.

**The request schema has no `self` field at all, and unknown fields are
rejected.** A body-supplied identity is exactly the vulnerability the
attestation exists to close, so an attempt to set one fails loudly rather than
being silently ignored.

**Inbound and outbound take different inputs.** An earlier draft used one schema
requiring an attestation in both directions, which is impossible: the initiator
must be *authorized* before it mints an attestation, so the attestation cannot
be an input to its own authorization. Order is **authorize → mint → send**.

| | Outbound | Inbound |
| --- | --- | --- |
| Question | "May I call this peer?" | "May this caller call me?" |
| Peer identity | `peer.peerId`, resolved **by the broker** | `peer.attestation`, verified per V1–V8 |
| Attestation | an **output** | an **input** |

## Not yet implemented

**Outbound authorization returns `501 sidecar.outbound_not_implemented`.** It
needs the broker's `peerId → binding` resolution and tier lookup, which is the
Phase 3 trust plane. It fails closed and a test asserts it never returns an
allow — an unimplemented authorization path that returned "yes" would be far
worse than one that returns an honest error.

Also outstanding: trust-tier enforcement, mandate evaluation (`canExecute`), MCP
proxying, and evidence records. See [BACKLOG.md](../../BACKLOG.md).

## Running

```bash
cd services
go build ./...
go test ./...

go run ./sidecar/cmd/satm-sidecar \
  -mesh satm-dev \
  -control-plane http://127.0.0.1:8080 \
  -broker http://127.0.0.1:8081 \
  -self-caid   "eip155:31337:0x…/42" \
  -self-peer   "12D3KooW…" \
  -self-binding "bnd_…"

curl http://127.0.0.1:8082/healthz
```

`self` comes from flags and this agent's own binding record. It is deliberately
not readable from a request.
