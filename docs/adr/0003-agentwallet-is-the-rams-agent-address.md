# ADR-0003: The ERC-8004 `agentWallet` is the ERC-8226 `agent` address

**Status:** Accepted
**Date:** 2026-08-22

## Context

ERC-8004 and ERC-8226 identify agents differently, and the two standards are explicitly agnostic
to each other:

- ERC-8004 identifies an agent by `agentId` — an ERC-721 `tokenId`. It also defines a reserved
  `agentWallet` metadata key: the address at which the agent receives payments, provable via
  EIP-712/ERC-1271 and automatically cleared on transfer.
- ERC-8226 identifies an agent by a plain `address`, used as the first key of
  `mandates[agent][principal]` and passed to `canExecute` and `recordExecution`.

SATM must decide which address plays the ERC-8226 `agent` role.

Options:

1. **A fresh, mandate-only address per agent.** Clean separation of duties, but creates a third
   identity with no on-chain link to `agentId`, so nothing ties a mandate to a registered agent
   or to its reputation.
2. **The ERC-721 owner address.** Wrong granularity: one owner may own many agents, so all of them
   would share mandates and caps.
3. **The ERC-8004 `agentWallet`.**

## Decision

**The agent's verified `agentWallet` is the address used as `agent` in all ERC-8226 calls.**

This is also the address the `SettlementEscrow` pays at release time, and the address an agent
uses as `clientAddress` when giving ERC-8004 feedback (which the standard itself recommends, so
agent-to-agent reputation aggregates correctly).

## Consequences

**Positive**

- A single verified address links identity, mandate, settlement, and reputation. Given an
  `agentId`, `getAgentWallet` yields everything needed to look up mandates and payouts.
- **Selling an agent neutralises its authority in SATM — but not in the registry.** Be precise
  here. ERC-8004 clears `agentWallet` on transfer, so payouts stop resolving and reconciliation
  revokes mesh access. The mandate rows keyed to the old address, however, **remain on-chain, and
  `canExecute` still returns `true` for them** — ERC-8226 has no notion of the agent identity
  behind an address.

  The gap is closed on-chain in two places: `AgentMandate` pins each wallet immutably to one
  `(registry, agentId)` and refuses to record executions once that identity stops resolving
  (§7.2b), and `TreasuryNote.agentSubscribe` requires `msg.sender == getAgentWallet(agentId)`.
  The pin is what stops the subtle version — registering a *fresh* `agentId` for the same wallet
  — which broker-side uniqueness alone could never have prevented, because a direct contract call
  involves no mesh binding at all. Principals SHOULD still call `revokeMandate`. See
  [SPECIFICATION.md §7.2b and §7.3.2](../../SPECIFICATION.md).
- Proving control of the mandate address is already solved: it is the same EIP-712/ERC-1271 proof
  ERC-8004 requires for `setAgentWallet`.

**Negative**

- **One mandate address per agent, and ERC-8226 permits at most one active mandate per
  `(agent, principal)` pair, scoped to exactly one asset.** An agent needing authority over three
  assets from the same principal cannot do it with one address. It needs either three principals
  or three agent identities.
- Payment address and authority address are the same key, which is more concentration than a
  production design would want. Mitigated in practice because `agentWallet` may be a smart
  contract wallet (ERC-1271), letting operators split duties behind it.
- **One wallet must back at most one agent.** If the same address were the `agentWallet` of two
  `agentId`s, ERC-8226's `(agent, principal)` keying would make those agents silently **share
  mandates and caps** — a spend by one would consume the other's allowance, with no error and no
  event to indicate it. The broker enforces uniqueness at binding time (check B9a); see
  [SPECIFICATION.md §7.2a](../../SPECIFICATION.md).

**On the multi-asset limitation**

This is a property of ERC-8226, not of our binding choice — any address selection has it. Rather
than paper over it, the prototype makes it *visible*: the demo deploys two assets, `TreasuryNote`
(mandated) and `EquityNote` (not mandated), and shows the equities purchase reverting on the
`asset != m.asset` branch of `canExecute`. That is exactly the concept brief's
"✗ Purchase Equities" outcome, and it falls out of the standard rather than out of bespoke logic.

Tracked as [SPECIFICATION.md OI-5](../../SPECIFICATION.md).
