# ADR-0002: Bind mesh identity to on-chain identity with two signatures

**Status:** Accepted
**Date:** 2026-08-22

## Context

An agent has two unrelated identities:

- a **libp2p PeerID**, attested by the SAM control plane inside a Biscuit;
- an **ERC-8004 `agentId`**, an ERC-721 token with a verified `agentWallet`.

Nothing connects them. Without a binding, on-chain reputation cannot be applied to a mesh peer,
and a mandate granted to an on-chain address cannot be enforced against a network connection.

Candidate approaches:

**(a) Chain-side claim only.** The registration file advertises a PeerID. Simple, and discoverable
chain-first — but a node can be advertised without its consent, and more importantly a *node*
cannot prove it is the advertised agent. Any peer could present that PeerID's address and claim
the associated reputation only if it also held the key, but the mesh has no way to check the
claim's on-chain half at all.

**(b) Node-side claim only.** The node signs "I am `agentId 42`". Proves control of the PeerID,
proves nothing about `agentId 42` — any node can claim any agent.

**(c) On-chain PeerID registry.** Write the PeerID into ERC-8004 on-chain metadata via
`setMetadata`. Authoritative and cheap to read, but costs a transaction per rotation, and still
does not prove the node holds the corresponding libp2p key.

**(d) Both signatures over one document.**

## Decision

**A binding is a single canonical document signed twice: once by the libp2p host key, once by the
ERC-8004 `agentWallet` via EIP-712. The on-chain registration file must independently advertise
the same PeerID.**

The wallet signature reuses the exact proof pattern ERC-8004 already defines for `setAgentWallet`
(EIP-712 with ERC-1271 fallback), so operators need no new key-management capability.

The registration-file advertisement is retained from (a) — not as a proof, but so that discovery
can start from the chain and resolve to transport without consulting the broker first.

## Consequences

**Positive**

- Forging a binding requires **both** the libp2p private key and the `agentWallet` key. Neither
  alone is sufficient (threats TH-1, TH-2).
- `meshId`, `controlPlane`, a single-use nonce, and a bounded expiry are inside the signed
  document, so a binding cannot be replayed onto another mesh or reused (TH-3).
- The `sidecarKey` rides inside the same document, so a hot, rotatable per-call signing key
  inherits its authority from both cold proofs without ever entering the on-chain path
  (§6.3.3, TH-7a).
- **Revocation on agent sale is free.** ERC-8004 clears `agentWallet` on ERC-721 transfer, so a
  sold agent's binding fails re-verification with no SATM-specific logic (TH-5).
- Key rotation works: reset the node key, re-bind, keep the `agentId` and its reputation — which
  is what "portable identity" actually means.

**Negative**

- Binding is a distinct operator step before enrollment, and enrollment must be sequenced after
  it. The broker rejects enrollments with no matching binding after a grace period.
- The binding is off-chain state held by the broker, so the broker is trusted for *admission*
  (TH-7). It is not trusted for value: on-chain enforcement is independent.
- Verification requires fetching the registration file, adding an SSRF surface and an availability
  dependency (TH-8, R-10).
- **The registry must itself be allow-listed, or the scheme is decorative.** Both signatures can
  be perfectly valid against a registry the *attacker* deployed. Check B2a therefore pins the
  accepted `(chainId, IdentityRegistry)` tuples, and the RPC target, EIP-712 domain, CAID, and
  every attested label derive from the matched tuple rather than from the document (TH-3a).
  This was missed in the first draft of this ADR and is the single most important correction to
  it.

## Rejected alternatives, briefly

(c) remains attractive for a production system: writing the binding on-chain would remove the
broker from the trust path for discovery entirely. It was rejected for v0.1 only because it costs
a transaction per rotation and still needs a PeerID-key proof, so it is strictly additive work on
top of this design rather than a replacement for it. It is listed in
[PLAN.md §13](../../PLAN.md) as a future direction.
