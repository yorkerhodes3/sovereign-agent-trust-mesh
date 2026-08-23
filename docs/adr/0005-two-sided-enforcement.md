# ADR-0005: Enforce trust at both admission and use

**Status:** Accepted
**Date:** 2026-08-22

## Context

SAM authorization is carried in Biscuit tokens minted by the control plane with a TTL (default
24 h, refreshed proactively). Facts inside a Biscuit — including SATM's attested `erc8004.*` and
`satm.*` labels — are fixed at mint time.

On-chain state is not fixed. Within a single Biscuit lifetime:

- a mandate can be revoked;
- an agent can be frozen by an enforcer;
- an agent's ERC-721 token can be transferred, clearing `agentWallet`;
- a cumulative cap can be consumed by other activity;
- reputation can move enough to change tier.

If the mesh were the only enforcement point, an agent could retain up to a full TTL of authority
it no longer has. If on-chain enforcement were the only point, unauthorized peers could still
consume mesh resources, discover services, and negotiate — and the concept brief's whole premise
is that trust should gate the *interaction*, not merely the settlement.

## Decision

**Trust is enforced at two independent points, with different latencies and different scopes.**

| Point | Enforced by | Scope | Revocation latency |
| --- | --- | --- | --- |
| **Admission** | Broker → control plane (`/admin/enrollments`, `/policies`, `/admin/revoke`) and node `attenuation` | Coarse: is this peer bound, on the right registry, at the right tier? | Biscuit TTL, or seconds via `/admin/revoke` |
| **Use** | SATM sidecar (inbound and outbound) and on-chain `recordExecution` | Fine: this tool, this asset, this action, this amount, right now | Immediate / atomic |

Concretely:

1. The broker gates enrollment, so an unbound peer never joins.
2. Node attenuation denies callers lacking broker-attested labels, at the transport layer.
3. The sidecar re-resolves the peer's binding **fresh** on every call, closing the TTL gap, and
   enforces per-tool tier requirements.
4. Mandate decisions are **never cached** — the sidecar reads `canExecute` at the current block.
5. The RAMS-aware asset calls `recordExecution` inside its transfer hook, which re-applies every
   check atomically and is authoritative.

## Consequences

**Positive**

- No single component's failure or compromise grants unauthorized asset movement. A compromised
  broker can admit a peer to the mesh; it cannot make the asset contract accept an invalid
  mandate.
- The TTL gap is closed without shortening the TTL, which would otherwise put avoidable load on
  the control plane.
- Failure modes decompose cleanly: broker down → no new authorizations, existing transport
  survives, no value moves ([SPECIFICATION.md §14.2](../../SPECIFICATION.md)).

**Negative**

- Every cross-organization tool call costs an extra sidecar hop and a broker round trip. Acceptable
  for a prototype; a production design would cache non-mandate decisions with a short TTL and push
  invalidations.
- Enforcement logic exists in three places (node Datalog, sidecar, contract), so a policy change
  must be reasoned about in all three. Mitigated by making the broker the single generator of node
  Datalog, and by keeping the on-chain rules purely a restatement of ERC-8226.
- `canExecute` at decision time means an RPC dependency on the hot path. This is deliberate:
  degraded mode denies rather than guesses ([SPECIFICATION.md §14](../../SPECIFICATION.md)).

## The asymmetry rule

Promotions are slow, demotions are immediate. A tier increase waits for confirmation depth; a
tier decrease, a revoked mandate, or a cleared `agentWallet` applies as soon as it is observed,
including across a reorg rollback. Trust should be hard to gain and easy to lose.
