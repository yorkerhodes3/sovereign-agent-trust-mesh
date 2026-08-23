# Research Notes — Verified Upstream Facts

These notes record what was **verified against primary sources** while writing
[SPECIFICATION.md](../SPECIFICATION.md) and [PLAN.md](../PLAN.md). Everything the design
depends on is listed here with a citation. Claims that could **not** be verified are marked
**UNVERIFIED** and are treated as risks in the plan, not as assumptions.

Verification date: **2026-08-22**.

---

## 1. Google SAM (`github.com/google/sam`)

Verified by shallow-cloning the repository at `master` and reading source, plus the Hugo docs
under `site/content/docs/`.

| Fact | Value | Source |
| --- | --- | --- |
| Description | "SAM Sovereign Agent Mesh" | GitHub repo metadata |
| License | Apache-2.0 | `LICENSE` |
| Support status | "Not an officially supported Google product." | `README.md` |
| Language | Go, module `github.com/google/sam`, Go 1.25+ | `go.mod` |
| Config schema version | `v1alpha1` | `api/policy.go`, docs |
| Binaries | `sam-control-plane`, `sam-router`, `sam-node`, `mcp-client` (also `sam-box`, `sam-console`, `nano-init` Dockerfiles) | `cmd/`, `Dockerfile.*` |
| Top-level packages | `agents/ api/ charts/ cmd/ development/ docs/ hack/ internal/ mobile/ sam-mcp-python/ site/ tests/` | repo root |
| Internal packages | `console controlplane identity node router sambox secrets skill storage` | `internal/` |

### 1.1 Transport and discovery

From `go.mod` direct dependencies:

- `libp2p/go-libp2p` — P2P host (TCP + QUIC)
- `quic-go/quic-go` — QUIC
- `libp2p/go-libp2p-kad-dht` — Kademlia DHT (peer/service discovery)
- `libp2p/go-libp2p-pubsub` — GossipSub
- `libp2p/go-libp2p-http`, `libp2p/go-libp2p-gostream` — HTTP / `net.Conn` over libp2p streams
- `pion/webrtc`, `pion/ice`, `pion/turn`, `pion/stun`, `pion/mdns` — NAT traversal + LAN discovery
- `flynn/noise` — libp2p Noise channel security (**not** TLS/mTLS)
- `modelcontextprotocol/go-sdk` — MCP
- `biscuit-auth/biscuit-go/v2` — Biscuit capability tokens

Topology is peer-to-peer with `sam-router` acting as libp2p bootstrap/relay anchors.
Agents are addressed by **libp2p PeerID** (`12D3KooW…`).

### 1.2 Node MCP tool surface (verified in source)

`internal/node/mcp.go` registers these tools on the node's local MCP endpoint:

| Tool | Line |
| --- | --- |
| `discover_remote_services` | `internal/node/mcp.go:79` |
| `get_mesh_info` | `internal/node/mcp.go:103` (also `internal/node/gate.go:136`) |
| `call_remote_tool` | `internal/node/mcp.go:109` |
| `find_remote_tools` | `internal/node/mcp.go:121` |
| `describe_remote_tool` | `internal/node/mcp.go:127` |

Service naming uses a URI scheme prefix validated as `type://name`
(`api.ValidateServiceFormat`, called from `internal/node/config.go:43`). Known types include
`mcp`, `inference`, and `a2a`.

### 1.3 Control-plane REST surface (verified in source)

`internal/controlplane/server.go:152-170` registers:

```
/healthz  /readyz  /metrics  /info  /register  /keys  /routers/lease  /policies
/enroll   /enroll/status     /refresh
/admin/bootstrap-tokens      /admin/enrollments      /admin/enrollments/{id}/{action}
/admin/revoke                /admin/status
/user/status                 /user/bootstrap-tokens  /user/revoke
```

`HandleAdminEnrollmentAction` (`server.go:1469`) parses `/admin/enrollments/{id}/{action}`,
requires admin auth, requires `POST`, requires the request to still be
`ENROLLMENT_STATUS_PENDING`, and supports actions including `reject` (and approve).

**This is the primary integration seam for the Trust Broker.**

### 1.4 Authorization pipeline (verified in source)

`internal/node/middleware.go`:

- `WithBiscuitAuth` (`:74`) wraps every inbound libp2p stream. It rate-limits, reads a protobuf
  `api.AuthFrame` containing the caller's Biscuit and a `TargetService`, then calls
  `VerifyBiscuitToken`.
- On success it responds with `api.AuthResponse{Success: true, Biscuit: n.GetIdentity()}` —
  i.e. **mutual authentication**: the responder returns its own control-plane-minted identity
  "so the caller can verify this node's attested facts (e.g. region) before sending request
  data" (`:136-139`).
- `VerifyBiscuitToken` (`:151`) checks a revocation cache (`n.revokedPeers`), then tries each
  trusted control-plane public key.
- `Authorize` (`:188`) builds the authorizer **from the caller's token**, then:
  - requires a `node("<peerID>")` fact bound to the connecting peer (`:203-209`) — token/peer binding;
  - injects `service(type, name)` for the requested target (`:221`);
  - injects `connection_peer_id` and `api.BaselineReplayCheck` (`:229-237`);
  - injects the **local** node's own identity facts, re-namespaced as `target_fact(key, value)`,
    via `injectIdentityFacts` (`:240`, `:322`, using `api.TargetFactRules`);
  - applies **local node policies/checks/rules from `sam-node.yaml`** (`:244-254`);
  - applies `api.BaselineTargetCheck` and `api.BaselinePolicies` (`:257-259`).

**Consequence relied upon by this design:** local `attenuation.checks` in `sam-node.yaml` are
evaluated against **the calling peer's** control-plane-attested facts. A check such as
`check if label("erc8004.agent_id", $id)` therefore constrains *who may call us*, based on facts
the control plane attested at enrollment time. The local node's own facts are separately
available as `target_fact(...)`, so the two cannot be confused.

### 1.5 Labels (verified in source)

`api/labels.go`:

- Labels are "free-form, control-plane-attested key=value metadata a node's identity carries".
- "SAM does not reserve or interpret any key" beyond validation.
- Key syntax: `^[a-zA-Z0-9_.-]{1,63}$` (`labelKeySyntax`, `:36`).
- Value: non-empty, `≤ 255` chars, must not contain `,`, `=`, or `\n\r\t` (`:54-65`).
- Matching is exact and case-sensitive.
- `api.LabelCheck(map[string]string)` (`api/datalog.go:461`) builds a fail-closed
  `check if label(k,v) or label(k2,v2)` disjunction.

`api/datalog.go:211` defines `FactLabel = "label"`, with documented example
`check if label("region", "us-east-1")`.

**Consequence:** `erc8004.agent_id`, `erc8004.registry`, `satm.trust_tier`, and `satm.mandate`
are all valid label keys, and CAIP-style values such as
`eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e` are valid label values
(66 chars, no forbidden characters).

### 1.6 Node config schema (verified in source)

`api/policy.go:32-52`:

```go
type ServiceConfig struct {
    Type        string            `yaml:"type"`
    Name        string            `yaml:"name"`
    Description string            `yaml:"description"`
    TargetURL   string            `yaml:"target_url,omitempty"`
    Command     []string          `yaml:"command,omitempty"`
    Env         map[string]string `yaml:"env,omitempty"`
}

type NodeConfig struct {
    Version     string          `yaml:"version"`
    Attenuation Attenuation     `yaml:"attenuation"`
    Services    []ServiceConfig `yaml:"services"`
}

type Attenuation struct {
    Policies []string `yaml:"policies"`
    Checks   []string `yaml:"checks"`
    Rules    []string `yaml:"rules"`
}
```

`internal/node/config.go` parses each attenuation string with the Biscuit Datalog parser at load
time, so **malformed policy fails fast at startup**.

### 1.7 Gaps and risks

| Item | Status |
| --- | --- |
| A2A support | `a2a` is an accepted service-type prefix, but no A2A integration guide or SDK binding was found. Treat A2A as **thin/experimental**. |
| Go plugin/interceptor API for third-party trust logic | **Not present.** There is no public extension interface, and `internal/` is not importable. Custom in-process logic would require a fork. |
| Client-side enforcement of the responder's returned Biscuit | The mutual-auth response exists (`AuthResponse.Biscuit`); the extent of initiator-side policy evaluation is **UNVERIFIED**. The design therefore does **not** depend on it, and performs initiator-side trust checks in the SATM sidecar instead. |
| Test coverage | Docs state testing is "intentionally minimal". |
| `--auto-approve-enrollment` | Defaults to permissive in the Helm chart; SATM **requires** it disabled. |

---

## 2. ERC-8004 — Trustless Agents

Source: <https://ercs.ethereum.org/ERCS/erc-8004>

### 2.1 Identity Registry

- ERC-721 + `ERC721URIStorage`. `tokenId` → `agentId`, `tokenURI` → `agentURI`.
- Global ID: `agentRegistry` = `{namespace}:{chainId}:{identityRegistry}` (e.g. `eip155:1:0x742…`), plus `agentId`.
- `register()` → `agentId`; emits `Registered(uint256 indexed agentId, string agentURI, address indexed owner)`.
- `setAgentURI(uint256 agentId, string newURI)`; emits `URIUpdated`.
- On-chain metadata: `getMetadata(agentId, key) → bytes`, `setMetadata(agentId, key, value)`; emits `MetadataSet`.
- **`agentWallet` is a reserved metadata key.** It cannot be set via `setMetadata()`. It is
  initially the owner's address and is changed only via
  `setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)` with an
  EIP-712 signature (EOA) or ERC-1271 (contract wallet) proving control of the new wallet.
- `getAgentWallet(agentId) → address`, `unsetAgentWallet(agentId)`.
- **`agentWallet` is automatically cleared on transfer** and must be re-verified by the new owner.

Registration file — required top-level shape:

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "...", "description": "...", "image": "...",
  "services": [ { "name": "A2A", "endpoint": "...", "version": "0.3.0" } ],
  "x402Support": false,
  "active": true,
  "registrations": [ { "agentId": 22, "agentRegistry": "eip155:1:0x742..." } ],
  "supportedTrust": ["reputation", "crypto-economic", "tee-attestation"]
}
```

The number and type of `services` entries are "fully customizable, allowing developers to add as
many as they wish" — this is what permits a `SAM` service entry.

Optional endpoint-domain verification: publish
`https://{endpoint-domain}/.well-known/agent-registration.json` containing a `registrations` list
matching the on-chain `agentRegistry` + `agentId`.

### 2.2 Reputation Registry

- `initialize(address identityRegistry_)`, `getIdentityRegistry()`.
- `giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)`
  - `valueDecimals` MUST be 0–18.
  - Submitter MUST NOT be the agent owner or an approved operator (anti self-review).
  - All fields except `value`/`valueDecimals` are OPTIONAL.
  - `endpoint`, `feedbackURI`, `feedbackHash` are **emitted but not stored**.
- `revokeFeedback(agentId, feedbackIndex)`,
  `appendResponse(agentId, clientAddress, feedbackIndex, responseURI, responseHash)`.
- Reads: `readFeedback`, `readAllFeedback`, `getSummary`, `getResponseCount`, `getClients`, `getLastIndex`.
- **`getSummary` requires a non-empty `clientAddresses` filter** — unfiltered aggregation is
  explicitly called out as Sybil-exposed. Any SATM scoring MUST supply an allow-list.
- Value is a signed fixed-point pair: `value=9977, valueDecimals=2` → `99.77`.
- Suggested `tag1` vocabulary includes `starred`, `reachable`, `ownerVerified`, `uptime`,
  `successRate`, `responseTime`, `revenues`, `tradingYield`.

### 2.3 Validation Registry

- `validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)`
  — MUST be called by owner/operator of `agentId`.
- `validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)`
  — MUST be called by the `validatorAddress` named in the request.
- `response` is `0..100`; may be used as binary (0 fail / 100 pass) or graded.
- May be called **multiple times** for the same `requestHash` (progressive finality via `tag`).
- Reads: `getValidationStatus`, `getSummary`, `getAgentValidations`, `getValidatorRequests`.
- Incentives/slashing are explicitly **out of scope**.

### 2.4 Stated security considerations

- Sybil attacks on reputation are possible; the ERC's contribution is a shared public schema, and
  it expects filtering by reviewer.
- On-chain pointers/hashes cannot be deleted → audit-trail integrity.
- The ERC "cannot cryptographically guarantee that advertised capabilities are functional and
  non-malicious."

### 2.5 Reference implementation

`github.com/erc-8004/erc-8004-contracts` — "Registry contracts curated by the 8004 team",
Hardhat + Ignition, TypeScript, **CC0**, ships `abis/`.

Contracts: `IdentityRegistryUpgradeable.sol`, `ReputationRegistryUpgradeable.sol`,
`ValidationRegistryUpgradeable.sol`.

Deterministic deployed addresses (identical across many chains):

| Registry | Mainnets | Testnets |
| --- | --- | --- |
| IdentityRegistry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |
| ReputationRegistry | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` | `0x8004B663056A597Dffe9eCcC1965A193B7388713` |

Chains listed include Ethereum, Base, Arbitrum, Abstract, Avalanche, BSC, Celo, Gnosis, GOAT,
Linea, Mantle, MegaETH (mainnet + testnet variants).

> **Important:** the published address table lists **only Identity and Reputation**. No canonical
> ValidationRegistry address is published, and the repo README warns that the Validation Registry
> portion of the spec is "still under active update and discussion with the TEE community". SATM
> therefore **deploys its own ValidationRegistry** and treats that interface as the most likely to
> churn.

---

## 3. ERC-8226 — Regulated Agent Mandate (RAMS)

Source: <https://eips.ethereum.org/EIPS/eip-8226> — status **Draft**.

Per project direction, this is treated as **normative** and assumed to be implemented. No public
reference implementation exists (a GitHub search for an ERC-8226/RAMS implementation returned zero
results), so SATM implements it from the EIP text.

### 3.1 Scope

A compliance delegation layer for AI agents operating on tokenized regulated assets. Agnostic to
agent identity system, token standard, and token compliance framework. Layer split:

| Layer | Responsibility | Standard |
| --- | --- | --- |
| Token compliance | Investor eligibility on this asset | ERC-7943 / ERC-3643 |
| Mandate compliance | Agent authority from this principal for this scope | ERC-8226 |
| Agent identity | Agent exists and is registered | ERC-8004 |

All implementations MUST implement ERC-165. Two interfaces, which SHOULD be deployed as separate
contracts.

### 3.2 `IComplianceProvider`

```solidity
enum ReasonCode {
  COMPLIANT, KYC_EXPIRED, AML_FLAG, NOT_ACCREDITED, NOT_QUALIFIED,
  JURISDICTION_BLOCKED, IDENTITY_NOT_FOUND, ATTESTATION_REVOKED, OTHER
}
event PrincipalGranted(address indexed principal, bytes32 indexed identityRef);
event PrincipalRevoked(address indexed principal, bytes32 indexed identityRef, ReasonCode reason);

function grantPrincipal(address principal, bytes32 identityRef, uint48 expiresAt) external;
function revokePrincipal(address principal, ReasonCode reason) external;
function checkPrincipal(address principal, bytes32 identityRef)
    external view returns (bool eligible, ReasonCode reason, uint48 expiresAt);
```

- `checkPrincipal` MUST return structured data — "a binary oracle is non-conformant".
- MUST verify `identityRef` resolves to a valid, unrevoked attestation.
- Provider is mandatory: `grantMandate` MUST revert if `complianceProvider == address(0)`.

### 3.3 `IAgentMandate`

```solidity
struct Mandate {
  address agent; uint48 validFrom; uint48 validUntil; address principal;
  bool revoked; address complianceProvider; bytes32 identityRef; address asset;
  uint256 maxTransactionValue; uint256 maxCumulativeValue; uint256 cumulativeUsed;
  bytes32 metadata;
}

struct GrantMandateParams {
  address agent; uint48 validFrom; uint48 validUntil; address principal;
  address complianceProvider; bytes32 identityRef; address asset;
  uint256 maxTransactionValue; uint256 maxCumulativeValue; bytes32 metadata;
  bytes32[] actions; uint256 deadline;
}

function grantMandate(GrantMandateParams calldata params, bytes calldata signature) external;
function revokeMandate(address agent, address principal, uint256 deadline, bytes calldata signature) external;
function extendMandate(address agent, address principal, uint48 newValidUntil, uint256 deadline, bytes calldata signature) external;
function freezeAgent(address agent) external;
function unfreezeAgent(address agent) external;
function setOperator(address principal, address operator, bool approved, uint256 deadline, bytes calldata signature) external;
function recordExecution(address agent, address principal, bytes32 action, uint256 amount) external;
function canExecute(address agent, address principal, address asset, bytes32 action, uint256 amount) external view returns (bool);
```

Events: `MandateGranted`, `ActionEnabled`, `MandateRevoked`, `MandateExtended`, `OperatorSet`,
`ExecutionRecorded`, `AgentFrozen`, `AgentUnfrozen`.

### 3.4 Normative rules that constrain the SATM design

1. **Storage is keyed by `(agent, principal)`; at most one active mandate per pair.**
   `grantMandate` MUST revert if the pair already has an active mandate.
2. **A mandate is scoped to exactly one `asset`.** `canExecute` returns false when
   `asset != m.asset`. Multi-asset authority requires multiple mandates.
3. Actions are `bytes32` labels, written into `actionEnabled[agent][principal][action]` at grant
   time. Prior actions MUST be cleared first. A new mandate starts `revoked=false`,
   `cumulativeUsed=0`.
4. `type(uint256).max` in a cap means "no limit".
5. Caps are denominated in **transfer quantity** — token amount for ERC-20/1155, count (1 per
   transfer) for ERC-721. Not USD, not token IDs.
6. `cumulativeUsed` MUST NOT reset on `extendMandate`. Resetting requires revoke + re-issue.
7. `extendMandate` MUST revert if `newValidUntil <= validUntil`.
8. `recordExecution` MUST only be callable by the mandate's `asset`, the principal's account, or an
   address holding the recorder role. It MUST re-apply all `canExecute` checks and revert on
   failure, and MUST revert on cap overflow.
9. Freezing MUST be restricted to enforcer roles; the enforcer address MUST be recorded in
   `AgentFrozen`. **The admin role governing enforcers MUST NOT be the same address as any enforcer.**
10. An approved operator MAY call `revokeMandate` and `extendMandate`.
11. `grantMandate` MUST revert if `complianceProvider.checkPrincipal` returns `eligible == false`.

### 3.5 Signed lifecycle operations

`grantMandate`, `revokeMandate`, `extendMandate`, `setOperator` may be called by the principal
directly (`msg.sender == principal`) or by any submitter with an EIP-712 principal signature.
Verification MUST be EIP-1271-compatible; the reference path is
`SignatureChecker.isValidSignatureNow(principal, digest, signature)` (handles EOAs, contract
wallets, and EIP-7702 delegated accounts).

Domain: `name = "RAMS"`, `version = "1"`, current `chainId`, `verifyingContract` = registry address.
Implementations MUST track `nonces[principal]` and include it in every signed operation, and MUST
revert if `block.timestamp > deadline` or the recovered signer != principal.

Normative typehashes:

```solidity
bytes32 constant GRANT_MANDATE_TYPEHASH = keccak256(
  "GrantMandate(address agent,uint48 validFrom,uint48 validUntil,"
  "address principal,address complianceProvider,bytes32 identityRef,"
  "address asset,uint256 maxTransactionValue,uint256 maxCumulativeValue,"
  "bytes32 metadata,bytes32[] actions,uint256 nonce,uint256 deadline)");
bytes32 constant REVOKE_MANDATE_TYPEHASH = keccak256(
  "RevokeMandate(address agent,address principal,uint256 nonce,uint256 deadline)");
bytes32 constant EXTEND_MANDATE_TYPEHASH = keccak256(
  "ExtendMandate(address agent,address principal,uint48 newValidUntil,uint256 nonce,uint256 deadline)");
bytes32 constant SET_OPERATOR_TYPEHASH = keccak256(
  "SetOperator(address principal,address operator,bool approved,uint256 nonce,uint256 deadline)");
```

### 3.6 Normative `canExecute` semantics

```solidity
function canExecute(address agent, address principal, address asset, bytes32 action, uint256 amount)
    public view returns (bool)
{
    Mandate storage m = mandates[agent][principal];
    if (m.principal == address(0)) return false;               // does not exist
    if (asset != m.asset) return false;                         // wrong asset
    if (block.timestamp < m.validFrom || block.timestamp > m.validUntil) return false;
    if (m.revoked) return false;
    if (!actionEnabled[agent][principal][action]) return false;
    if (isFrozen(agent)) return false;
    if (m.maxTransactionValue != type(uint256).max && amount > m.maxTransactionValue) return false;
    if (m.maxCumulativeValue != type(uint256).max && m.cumulativeUsed + amount > m.maxCumulativeValue) return false;
    return true;
}
```

RAMS-aware regulated tokens consult the registry **inside their existing pre-transfer compliance
hook**.

---

## 4. Open questions carried into the plan

| # | Question | Where it is handled |
| --- | --- | --- |
| Q1 | Does the SAM initiator evaluate the responder's returned Biscuit against local policy? | Not relied upon; the SATM sidecar performs initiator-side checks. Spike in Phase 1. |
| Q2 | Exact request/response schema of `POST /admin/enrollments/{id}/approve`, including whether labels can be attested at approval time. | Phase 1 spike; fallback is `/policies` + bootstrap-token pre-provisioning. |
| Q3 | Will the ERC-8004 ValidationRegistry interface change after the TEE-community revision? | Isolated behind `ValidationPort`; Phase 4 only. |
| Q4 | Will ERC-8226 change before Final? | Interfaces vendored verbatim + a conformance suite derived from the EIP's MUST clauses. |
| Q5 | Go 1.25 toolchain availability in CI. | Pinned in `.tool-versions`; SAM consumed as a released binary/container where possible. |
