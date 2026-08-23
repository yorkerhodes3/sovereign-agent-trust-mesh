# Demo Script

The scripted scenario that proves the prototype. Run with `make demo`.

Everything below is the target behaviour defined by [SPECIFICATION.md](../SPECIFICATION.md) and
built by [PLAN.md](../PLAN.md) Phase 6. It doubles as the acceptance walkthrough: each act maps to
acceptance criteria A1–A9 and to the negative controls N-1…N-10.

---

## Cast

| Actor | Org | Role | Trust tier | Authority |
| --- | --- | --- | --- | --- |
| **Atlas** | Acme Corp treasury | Client agent; holds a RAMS mandate from Acme's CFO | T2 | `active` |
| **Vault** | Bellwether Custody | Server agent; offers `mcp://custody` | T3 | `none` |
| **Meridian** | Meridian Custody | Server agent; competitor, Sybil-inflated reputation | T1 | `none` |
| **Auditor** | Cirrus Validation | Validator agent; re-executes quotes | T3 | `none` |
| **Mallory** | — | Rogue agent; unregistered | T0 | `none` |
| **Acme CFO** | Acme Corp | Principal; KYC-verified in `ComplianceProvider` | — | — |

Note the two axes ([SPECIFICATION.md §5.2](../SPECIFICATION.md)). Atlas is **T2** — a competent
client with a modest track record — yet it is fully authorized to move treasury assets, because
its authority comes from its KYC-verified principal, not from its reputation. Vault is **T3 with
no mandate at all**, because it is a service provider, not a delegate. Neither needs the other's
property, and the demo would be wrong if it implied otherwise.

---

## Setup (`make devnet-up`)

Two Anvil chains (L2 role, L1 role), Postgres, IPFS, Dex, `sam-control-plane`
(**`--auto-approve-enrollment=false`**), `sam-router`, `satm-broker`, `satm-indexer`, and one
`sam-node` + `satm-sidecar` per agent.

Contracts deployed: ERC-8004 registries, `AgentMandate`, `ComplianceProvider`, `TreasuryNote`,
`EquityNote`, `MockUSD`, `SettlementEscrow`, `ReplayValidator` on L2; `AuditAnchor` on L1.

---

## Act I — Onboarding *(A3)*

Each legitimate agent is registered and bound:

```bash
satm-cli register-agent --name "Bellwether Vault" --skill treasury-custody
# → agentId 42

satm-cli publish-registration --agent-id 42 --peer-id 12D3KooW…B --mesh satm-dev
# → ipfs://bafy…  ; setAgentURI(42, ipfs://bafy…)

satm-cli bind --agent-id 42 --node-data-dir /var/lib/sam-node-b
# signs the binding document with the libp2p host key AND the agentWallet (EIP-712)
# → binding accepted · tier t1-registered
```

Only then does the node enroll. The broker matches the pending enrollment's PeerID to the binding
and approves it with attested labels.

**Observe:** decode the minted Biscuit — it carries
`label("erc8004.agent_id", "42")`, `label("erc8004.registry", "eip155:…")`,
`label("satm.trust_tier", "t1-registered")`. The node never asserted these; the control plane
minted them because the broker verified them.

> ### ❌ N-1 — Mallory tries to join
> Mallory starts a `sam-node` and enrolls with a valid OIDC identity, but has no binding.
> After the 10-minute grace period the broker rejects the enrollment.
> **Mallory never gets a Biscuit and cannot address any peer.**

> ### ❌ N-2 — Mallory claims to be agent 42
> Mallory constructs a binding document naming `agentId 42` and signs it with her own libp2p key.
> She cannot produce the second signature, because check **B9** requires an EIP-712 signature from
> `getAgentWallet(42)` — Bellwether's key.
> **Rejected with `binding.wallet_signature_invalid`.**

> ### ❌ N-9 — Binding replay
> Mallory obtains Bellwether's *published, fully signed* binding document and submits it to a
> second mesh (`satm-prod`).
> Rejected at **B2** (`meshId` mismatch — it is inside the signed payload). Resubmitting it to
> `satm-dev` is rejected at **B3/B15** (nonce already consumed). And because B1 caps
> `expiresAt` at `issuedAt + maxTTL`, no signer can mint a document that outlives the nonce
> record and becomes replayable later.

> ### ❌ N-11 — Mallory brings her own "registry"
> Mallory deploys her own ERC-8004-shaped contract, mints herself `agentId 42` with an
> `agentWallet` she controls, publishes a matching registration file advertising her PeerID, and
> submits a binding that is **internally perfectly consistent** — both signatures valid, file
> matches, every structural check passes.
>
> Rejected at **B2a**, before a single chain read: her registry tuple is not in
> `binding.trustedRegistries`. This is why the broker derives the RPC target, the EIP-712 domain,
> the CAID, and every attested label from the *allow-listed* tuple rather than from the document.
> Had the document's own `agentRegistry` been trusted, this attack would have worked perfectly —
> which is exactly why B2a exists.

---

## Act II — Discovery and reputation *(A1, A4)*

Atlas needs a custodian. It does not scan the mesh; it queries the chain.

```
satm_discover_agents { skill: "treasury-custody", minTier: "t3-validated" }
```

| Candidate | On-chain score | Distinct clients | Curated reviewers | Validations | Live on mesh | Selected |
| --- | --- | --- | --- | --- | --- | --- |
| **Vault** | 87.4 | 5 | 5 | 3 passing | yes | ✅ |
| **Meridian** | 99.0 | **3** | **0** | 0 | yes | ❌ |
| Northwind | 91.2 | 4 | 4 | 2 passing | **no** | ❌ |

> ### ❌ N-8 — Sybil inflation
> Meridian's operator runs the *serious* version of this attack, not the toy one. They register
> **three** ERC-8004 agents, bind all three, and have them post 100/100 feedback for Meridian.
> ERC-8004 registration is permissionless, so this costs almost nothing — and it satisfies
> `minDistinctClients = 3`.
>
> It still fails. `getSummary` is filtered by the mesh's **curated** reviewer roster, and three
> brand-new self-registered agents are not on it, so `w(client) = 0` for all three and they
> contribute nothing to the score.
> **Meridian stays at T1 with a headline on-chain score of 99 and is never offered to Atlas.**
>
> The naive variant — ten reviews from one address — is tested too, but it is not the real threat.
> A distinct-client minimum alone would **not** have stopped this attack, and an allow-list of
> "any bound agent" would not have either. That is why the roster is curated
> ([SPECIFICATION.md §5.3](../SPECIFICATION.md)).

Northwind is excluded for a different reason entirely: it is trustworthy but **offline**. On-chain
registration proves identity, not liveness — so discovery intersects the ranked chain results with
SAM's live `discover_remote_services`.

---

## Act III — Trust-gated connection *(A2)*

Atlas calls `quote_treasury_note` on Vault. The request traverses:

```
Atlas → sidecar A  (1. authorize outbound  2. mint call attestation) → sam-node A
      → libp2p/Noise + Biscuit AuthFrame
      → sam-node B (WithBiscuitAuth → attenuation checks against Atlas's labels)
      → sidecar B  (3. verify attestation V1–V8  4. authorize inbound) → Vault
```

Note the order on the initiator side: **authorize, then mint**. The attestation cannot be an input
to its own authorization, which is why outbound and inbound `/v1/authorize` take different peer
inputs — outbound a PeerID the broker resolves itself, inbound the attestation
([SPECIFICATION.md §6.3.4](../SPECIFICATION.md)).

Vault's `sam-node.yaml` carries broker-generated attenuation:

```yaml
attenuation:
  checks:
    - 'check if label("erc8004.agent_id", $id)'
    - 'check if label("satm.trust_tier", "t2-reputable") or label("satm.trust_tier", "t3-validated")'
  policies:
    - 'deny if label("satm.trust_tier", "t0-unverified")'
```

Atlas is T2, so it clears the check. Authority is **not** checked here — `quote_treasury_note` is
a read tool, and the mandate is enforced only where it matters (§Act IV).

> ### ❌ N-3 — Under-tiered caller
> Meridian (T1) calls `mcp://custody`, which requires T2. The stream is denied inside
> `WithBiscuitAuth` before any MCP payload is read — the tier check fails against Meridian's
> attested labels. Even if transport were permitted, sidecar B would deny it independently.
> **Two layers, either sufficient.**

> ### ❌ N-12 — Attestation replay
> Mallory captures Atlas's call attestation off the wire and replays it against a *different*
> custodian. Rejected at **V2**: `targetCaid`, `targetPeerId`, and `targetBindingId` are inside
> the signature and do not match the new callee. Replaying it at Vault with mutated arguments
> fails **V4** (`argsHash`); replaying it verbatim 60 s later fails **V7** (freshness) and **V8**
> (the nonce was consumed atomically before the first request was forwarded).

> ### ❌ N-18 — Attestation scope escalation
> Mallory obtains a legitimate attestation for the cheap read tool `quote_treasury_note`, then
> presents it on a `subscribe_treasury_note` call. Rejected at **V3**: `service` and `tool` are
> inside the signature *and* the verifier compares them to the request actually being served.
> **Signing a field is worthless unless the verifier checks it** — an earlier draft signed
> `service`/`tool` but never compared them, which made this attack work.

> ### ❌ N-13 — Spoofed `self`
> Mallory reaches the broker directly and posts `/v1/authorize` claiming `self` = Atlas's CAID.
> The field is ignored — the broker derives `self` from the authenticated sidecar channel, and
> Mallory holds no sidecar credential. On the outbound path she also cannot name a peer CAID at
> all: she supplies a PeerID and the *broker* resolves it through its own binding table.

---

## Act IV — Delegated authority *(A5)*

Acme's CFO granted Atlas a mandate:

```
agent               = Atlas's agentWallet
principal           = Acme CFO
complianceProvider  = ComplianceProvider   (CFO is COMPLIANT, expiry 2027-01-01)
asset               = TreasuryNote
actions             = [SUBSCRIBE, REDEEM]
maxTransactionValue = 250,000 TNOTE
maxCumulativeValue  = 1,000,000 TNOTE
validUntil          = +90 days
metadata            = keccak256(mandate legal text)
```

Atlas checks before acting:

```
satm_check_mandate { asset: TNOTE, action: SUBSCRIBE, amount: 250000e6 }
→ { canExecute: true, checkedAtBlock: 9123460, ttlSeconds: 0 }
```

`ttlSeconds: 0` — mandate decisions are never cached.

Atlas subscribes via `agentSubscribe(agentId, principal, amount)`. `TreasuryNote` first
**authenticates the agent** — `require(msg.sender == getAgentWallet(agentId))` — then re-checks
the principal's current eligibility, then calls `canExecute`, then `recordExecution`, which
re-applies every check atomically and increments `cumulativeUsed` to 250,000.

> ### ❌ N-4 — Equities
> Atlas attempts `agentSubscribe` on `EquityNote`.
> `canExecute(agent, principal, EquityNote, SUBSCRIBE, …)` returns `false` at the
> `asset != m.asset` branch. **The transaction reverts with `TN: mandate denies`.**
>
> No SATM code implements this rule. It is ERC-8226's per-asset mandate scoping doing exactly what
> the concept brief asked for: *"✗ Purchase Equities"*.

> ### ❌ N-5 — Cumulative cap
> Atlas performs three more 250,000 subscriptions (cumulative 1,000,000 — at the cap), then
> attempts one more. The off-chain pre-check says no; forcing the transaction anyway **reverts at
> the asset's `canExecute` guard** with `TN: mandate denies`.
>
> The demo then does something the happy path cannot reach: it calls `recordExecution`
> **directly**, as an authorized recorder, with the same over-cap amount — and that reverts too.
> This matters because it proves the registry defends itself rather than trusting every asset to
> check first.
>
> (An earlier draft of this script claimed the *asset* path reverted inside `recordExecution`.
> It does not — the asset's own `canExecute` fires first. Both layers are real; they catch
> different callers. See [SPECIFICATION.md §9.5](../SPECIFICATION.md).)

> ### ❌ N-6 — Mid-session revocation
> While Atlas is mid-workflow, the CFO calls `revokeMandate`. Atlas's next action fails **in the
> very next block** — no cache to expire, no token to wait out.

> ### ❌ N-15 — KYC revoked after the grant
> Acme's compliance officer revokes the CFO's principal eligibility. ERC-8226's `canExecute`
> **still returns `true`** — the standard consults `IComplianceProvider` only at `grantMandate`,
> so a mandate can outlive the KYC that justified it.
>
> `agentSubscribe` nevertheless reverts with `TN: principal not currently eligible`, because the
> asset re-checks `checkPrincipal` at execution time (§7.3 step 2a).
> **This is a gap in the draft standard, and SATM closes it in the token layer — the only layer
> that can enforce it atomically.** It is flagged as an extension, not a conformance claim.

---

## Act V — Settlement and reputation *(A6)*

```
openJob(jobId, agentId=42, MockUSD, 500e6, deadline)  →  fund
        → Vault markDelivered(resultHash)
        → Atlas release  →  JobSettled
```

Payout resolves `getAgentWallet(42)` **at release time**.

Atlas then posts feedback — `starred 87/100`, tagged `treasury-custody` — with an IPFS feedback
file containing a `proofOfPayment` block naming the settlement transaction. Atlas signs as a
client using **its own `agentWallet`**, per ERC-8004, so agent-to-agent reputation aggregates.

Meanwhile Auditor picks up Vault's `ValidationRequest`, re-executes the quote deterministically,
and calls `validationResponse(requestHash, 100, …)`.

**Vault's reputation is now backed by demonstrable economic activity and independent verification
— not by self-assertion.**

---

## Act VI — Audit *(A7)*

Every decision in Acts I–V was appended to the hash-chained evidence log, **co-signed by both
counterparties' sidecars**. The anchoring job Merkleises the batch and calls
`AuditAnchor.anchor(root, fromSeq, toSeq, uri)` on L1.

```bash
satm-cli evidence proof --id ev_01J…
# → record hash, Merkle path, root, L1 tx, block
```

A regulator can verify **inclusion and post-anchor immutability** of any single authorization
decision against an L1 commitment, without trusting the broker, the mesh, or either organization.
Tool arguments are stored as `argsHash` only, so the trail is verifiable without being an
exfiltration channel.

Being honest about the limit: **the anchor proves the broker committed to those bytes, not that
the bytes are true or complete.** A compromised broker could fabricate or omit records *before*
anchoring. That is why each record carries counterparty signatures and why `fromSeq`/`toSeq` are
monotonic and gap-free on-chain — a counterparty holding a signed receipt for a decision missing
from an anchored batch has positive evidence of omission. Detection, not prevention
([SPECIFICATION.md §12.3](../SPECIFICATION.md), OI-11).

---

## Act VII — Failure and revocation *(A8, A9)*

> ### ❌ N-7 — Agent sold to an attacker
> Bellwether transfers agent NFT 42 to Mallory. ERC-8004 **automatically clears `agentWallet`** on
> transfer. Two things follow, at different speeds:
>
> - **Immediately, on-chain:** the old wallet's `agentSubscribe` reverts, because the asset
>   requires `msg.sender == getAgentWallet(agentId)` and that is now `address(0)`. Settlement
>   payouts fail for the same reason.
> - **Within one reconciliation interval:** the broker observes `getAgentWallet(42) == 0`, revokes
>   the binding, and calls `POST /admin/revoke`, removing mesh access.
>
> **Mallory owns the token and inherits nothing: no mesh access, no payouts, no usable authority.**
>
> What does *not* happen, stated precisely: the mandate rows keyed to the old wallet remain
> on-chain, and `canExecute` still returns `true` for them — ERC-8226 has no notion of the agent
> identity behind an address. Nothing SATM operates will act on that, but a principal SHOULD still
> call `revokeMandate`, and the operator runbook says so.
>
> This is the most important moment in the demo — on-chain state change propagating into live
> network access control, which is precisely the capability the concept brief identifies as
> missing today.

> ### ❌ N-14 — Quiet decommission
> Bellwether removes the `SAM` service entry from agent 42's registration file, intending to
> retire that node without telling anyone. Verification required that advertisement (check B12),
> so reconciliation re-runs the **full** B10–B13 check, finds it gone, and revokes within one
> interval.
> **Removing the advertisement is a supported revocation path, not a silent no-op** — which it
> would have been if reconciliation only re-read the `active` flag.

> ### ❌ N-10 — Chain unavailable
> Kill the L2 RPC. The indexer stalls, head lag crosses the threshold, and the broker enters
> degraded mode: no new bindings, no tier promotions, and **every mandate-bearing authorization
> denies immediately**, because a mandate decision requires a live `canExecute`.
> Existing conversations continue and **no value moves**. Past `degraded.maxAge` (15 min) *all*
> authorizations deny, and every decision served in the interim is stamped `stale=true` in the
> evidence log so the trade-off is auditable afterwards.

---

## Scorecard

| Criterion | Act | Result |
| --- | --- | --- |
| A1 Dynamic discovery | II | Chain-first, liveness-intersected |
| A2 Secure communication | III | libp2p/Noise + Biscuit + attenuation |
| A3 Portable identity | I | `agentId` survives node key rotation |
| A4 Reputation-based selection | II | Sybil candidate with three self-registered reviewers rejected |
| A5 Verifiable delegation | IV | Treasury allowed; equities, cap, and revoked KYC all denied |
| A6 Automated settlement | V | Escrow released; feedback carries payment proof |
| A7 Full auditability | VI | L1-anchored Merkle proof + counterparty receipts |
| A8 Revocation | IV, VII | Mandate: 1 block. Binding, and advertisement removal: 1 interval |
| A9 Fail-closed | VII | Asset actions deny immediately; everything denies past `degraded.maxAge` |
| A10 Impersonation resistance | I, III | Foreign registry, attestation replay, and spoofed `self` all rejected |

Negative controls N-1 … N-18: all denied, each at a named layer.

### What the demo deliberately does not claim

- The audit anchor proves **inclusion and post-anchor immutability**, not that the broker recorded
  the truth or recorded everything. Omission is *detectable* via counterparty receipts, not
  prevented ([SPECIFICATION.md §12.3](../SPECIFICATION.md)).
- The reviewer roster is **operator-curated**. That resists cheap Sybils but not a compromised or
  co-opted curated reviewer.
- `ComplianceProvider` is a stub. Real KYC is out of scope.
- A transferred agent's mandate rows persist on-chain; SATM's assets refuse to act on them, but a
  different RAMS-aware asset that skips the `getAgentWallet` liveness check would not.
