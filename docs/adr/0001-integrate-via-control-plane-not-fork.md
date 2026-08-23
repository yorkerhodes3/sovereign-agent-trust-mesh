# ADR-0001: Integrate with SAM via documented seams, not a fork

**Status:** Accepted
**Date:** 2026-08-22

## Context

SATM needs on-chain trust to gate SAM mesh traffic. Three integration options exist:

1. **Fork SAM** and add trust checks directly to the node's authorization middleware.
2. **Use a Go plugin/interceptor API** to inject custom trust logic.
3. **Integrate through documented HTTP endpoints and configuration.**

Option 2 was investigated and **does not exist**. SAM exposes no public plugin or interceptor
interface, and its implementation lives in `internal/`, which Go makes non-importable from
outside the module. Adding one would itself be a fork.

Option 1 is technically the most powerful. `internal/node/middleware.go` `Authorize()` is exactly
where a per-request on-chain check would go. But SAM is `v1alpha1`, explicitly "not an officially
supported Google product", and its docs state testing is "intentionally minimal". A fork would
need continuous rebasing against a fast-moving, pre-1.0 upstream, and every rebase would risk
silently breaking a security control.

Option 3 is viable because SAM exposes three real seams, verified in source
(see [RESEARCH-NOTES.md §1.3–1.6](../RESEARCH-NOTES.md)):

- `POST /admin/enrollments/{id}/{action}` — admission control, when the control plane runs with
  `--auto-approve-enrollment=false`.
- `POST /policies` and `POST /admin/revoke` — role projection and immediate revocation.
- `attenuation.{policies,checks,rules}` in `sam-node.yaml` — local Datalog evaluated against the
  **caller's** control-plane-attested facts, which is a genuine inbound authorization hook.

## Decision

**SATM integrates with SAM exclusively through documented HTTP endpoints and `sam-node.yaml`.
We do not fork SAM.**

Where those seams are insufficient for fine-grained decisions — for example, checking a mandate's
remaining cumulative cap for a specific tool call — the enforcement moves into the SATM sidecar,
which sits in the MCP path and is entirely ours.

All SAM-facing code is confined to `services/broker/samclient` so that upstream churn has one
blast radius.

## Consequences

**Positive**

- SAM can be upgraded by changing a pinned version, not by resolving merge conflicts in security
  code.
- The integration is reproducible by anyone using stock SAM binaries or containers.
- Contributing the pattern upstream stays possible, because we depend only on its public contract.

**Negative**

- Trust checks cannot run per-message inside the node. Node-level enforcement is coarse (labels
  and tiers, refreshed at Biscuit TTL), and fine-grained checks cost an extra sidecar hop.
- We depend on the control plane being run with manual approval enabled — a deployment
  requirement, not a code guarantee. The broker asserts it at startup.
- Revocation through `/admin/revoke` has seconds of latency rather than being instantaneous.

**Mitigations**

- The sidecar provides fine-grained, immediate enforcement ([ADR-0005](0005-two-sided-enforcement.md)).
- On-chain `recordExecution` is authoritative for anything that moves value, so the worst case for
  a stale mesh decision is unauthorized *conversation*, not unauthorized *value transfer*.
- A CI regression test (spike S-2) fails the build if an upstream change breaks caller-label
  evaluation.

## Revisit if

SAM publishes a stable plugin/interceptor API, or reaches a supported release with a policy
extension point for per-request external checks.
