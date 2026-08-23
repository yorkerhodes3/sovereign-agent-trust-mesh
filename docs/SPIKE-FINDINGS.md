# Phase 1 Spike Findings

**Date:** 2026-08-23
**SAM commit under test:** `google/sam` @ `master` (cloned 2026-08-23), Go 1.25.14
**Status:** S-1, S-2, S-3, S-5 **closed**. S-4 closed in Phase 0.

All four spikes were run against a **real SAM mesh** built from source — one
`sam-control-plane`, one `sam-router`, three `sam-node` instances — not against
mocks and not by reading code alone. Where a conclusion rests on source rather
than observed behaviour, it says so.

The headline: **the single assumption most likely to invalidate the design holds.**
Node-level attenuation really does evaluate the *caller's* control-plane-attested
labels, and denies at the transport layer.

---

## Summary

| Spike | Question | Result |
| --- | --- | --- |
| **S-1** | Can labels be attested at enrollment approval? | **Yes** — declared by node, attested by admin. The spec's "fallback" path is the *only* path. |
| **S-2** | Does node attenuation evaluate the caller's labels? | **Yes — confirmed live.** Denies before any payload is read. |
| **S-3** | Does the initiator evaluate the responder's Biscuit? | **Yes** — opt-in per call, fails closed. Better than assumed. |
| **S-5** | Does a local MCP service learn the caller's PeerID? | **No** — dumb-pipe proxy. Call Attestation is therefore mandatory. |

One upstream defect was found that blocks bootstrap enrollment entirely (§6).

---

## S-1 — Enrollment approval and label attestation

**Resolves OI-1.**

### Mechanism

Labels are **declared by the node** and **attested by the admin at approval**.
`api/sam.proto` states it outright:

```proto
message BootstrapEnrollRequest {
  string bootstrap_token = 1;
  string peer_id         = 2;
  bytes  public_key      = 3;
  string requested_role  = 4;
  // Operator-declared labels; the admin approving the enrollment attests
  // them (see EnrollRequest.labels).
  map<string, string> labels = 5;
}
```

and `internal/controlplane/server.go` confirms it in the approve branch:

```go
// Admin approval is the attestation of the operator-declared labels
// recorded on the pending request.
biscuitBytes, err := identity.MintBootstrapBiscuitToken(
    privKey, pID, tokenRecord.Role, expiry, policyRoles, enrollReq.Labels)
```

A node declares labels with `sam-node run --labels "k=v,k2=v2"`. **The flag is on
`run`, not on `join`** — worth knowing, because the obvious guess is wrong.

### Observed

Node started with:

```
--labels erc8004.agent_id=42,\
         erc8004.registry=eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e,\
         satm.trust_tier=t3-validated
```

`GET /admin/enrollments` (admin bearer token) returned the pending request with the
declared labels visible — which is exactly what the broker needs in order to
compare them against a verified binding before deciding:

```json
{
  "ID": "93b72102-…", "PeerID": "12D3KooWALK8sCkh…", "Status": 1,
  "Labels": {
    "erc8004.agent_id": "42",
    "erc8004.registry": "eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e",
    "satm.trust_tier": "t3-validated"
  }
}
```

`POST /admin/enrollments/{id}/approve` with an **empty body** → `200 Enrollment approved`.

Decoding the minted Biscuit shows the labels present as control-plane-signed facts:

```
facts: [
  expiration(2026-08-24T18:13:51Z)
  node("12D3KooWALK8sCkhrtSPaivF8FQamrrcZJyUwRZMEtrYK5NzCP3N")
  client_peer_id("12D3KooWALK8sCkhrtSPaivF8FQamrrcZJyUwRZMEtrYK5NzCP3N")
  label("erc8004.agent_id", "42")
  label("erc8004.registry", "eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e")
  label("satm.trust_tier", "t3-validated")
  role("sam:role:node")
  granted_service_all_types()
  target_unrestricted()
]
```

### Consequences for SATM

1. **The specification's "primary path" does not exist.** Labels cannot be supplied
   *in* the approve call. [SPECIFICATION.md §6.1.3](../SPECIFICATION.md) offered a
   primary and a fallback; only the fallback is real. §6.1.3 has been corrected.
2. **The trust property is unchanged**, which is why this is a correction and not a
   redesign. A node may declare `erc8004.agent_id=999`, but the broker approves only
   if the declaration matches a verified binding, and rejects otherwise. Approval is
   the gate; declaration is just an input to it.
3. **CAID values survive intact.** `eip155:84532:0x8004a818…` round-tripped through
   flag parsing, protobuf, storage, and Biscuit minting unchanged — colons and all.
   This was an open risk given SAM's label-value constraints.
4. Biscuit TTL observed as **24h**, matching the documented default.

---

## S-2 — Node attenuation evaluates the caller's labels

**Resolves OI-2. This is the load-bearing spike.**

If this had failed, [ADR-0001](adr/0001-integrate-via-control-plane-not-fork.md)
(integrate via documented seams, no fork), the defence-in-depth model in
[§10.3](../SPECIFICATION.md), and negative control N-3 would all have needed
reworking.

### Setup

Three enrolled nodes, each with a distinct attested `erc8004.agent_id`:

| Node | Attested `erc8004.agent_id` | Role in test |
| --- | --- | --- |
| A | `42` | caller that SHOULD be allowed |
| B | `99` | callee — carries the attenuation check |
| C | `777` | caller that SHOULD be denied |

Node B's `sam-node.yaml`:

```yaml
version: "v1alpha1"
services:
  - type: mcp
    name: custody
    command: ["npx", "-y", "@modelcontextprotocol/server-everything"]
attenuation:
  checks:
    - 'check if label("erc8004.agent_id", "42")'
```

### Result

**Test 1 — A (`agent_id=42`) → B: ALLOWED.** Returned B's full tool catalogue
(`mcp://custody/echo`, `…/get-sum`, and 11 more). Node B logged:

```
Audit Traceability {"peer_id": "12D3KooWESdQzbov…", "role": "sam:role:node",
                    "target": "mcp://custody", "protocol": "/sam/mcp/1.0.0"}
```

**Test 2 — C (`agent_id=777`) → B: DENIED.** Client saw:

```
fetch remote service catalog: auth rejected by 12D3KooWETadEYZD…:
  biscuit: verification failed: failed to verify check #1:
  check if label("erc8004.agent_id", "42")
```

Node B logged:

```
[Auth] AuthZ Denied 12D3KooWGRdGJHH86vp8ifKUb4VeLmiMswQLqSoTUWmwuj7jVwxn:
  biscuit: verification failed: failed to verify check #1:
  check if label("erc8004.agent_id", "42")
```

### Consequences for SATM

1. **Confirmed: `attenuation.checks` are evaluated against the CALLER's
   control-plane-attested facts.** The source reading in
   [RESEARCH-NOTES §1.4](RESEARCH-NOTES.md) was correct.
2. **Denial happens before any MCP payload is processed** — at
   `internal/node/middleware.go` `WithBiscuitAuth`, during the auth handshake.
3. **It gates the service catalogue too, not just service calls.** Node C was denied
   at `system://sam.catalog`, so an under-tiered peer cannot even enumerate what a
   node offers. That is stronger than [§10.2](../SPECIFICATION.md) claimed, and it
   materially improves N-3: a denied caller learns nothing.
4. The label vocabulary in §6.1.3 works verbatim as Datalog. No escaping needed.

---

## S-3 — Initiator-side verification of the responder

**Resolves OI-2's second half. Outcome is better than the specification assumed.**

The spec previously said initiator-side evaluation was UNVERIFIED and deliberately
did not depend on it. It exists.

`internal/node/labels_gate.go` implements `VerifyPeerLabels`, which takes the
responder's Biscuit from the mutual-auth handshake, verifies it against trusted
control-plane keys, applies `api.LabelCheck(required)`, and authorizes. It is
exposed as the `required_labels` argument on `call_remote_tool`, documented as:

> "Fails closed: the call is rejected unless the peer attests any one of them."

### Result

**Test 3a — A calls B requiring `erc8004.agent_id=99` (true of B): SUCCESS.**

```
Echo: satm-s3
```

**Test 3b — A calls B requiring `erc8004.agent_id=12345` (false): DENIED.**

```
failed after 3 retries: provider 12D3KooWETadEYZD… has no attested label
matching map[erc8004.agent_id:12345]: biscuit: verification failed:
failed to verify check #0: check if label("erc8004.agent_id", "12345")
```

### Consequences for SATM

1. SATM gains a **second enforcement layer for free**. The sidecar's outbound check
   (§6.3.2) can pass `required_labels` to `call_remote_tool` so SAM enforces the peer's
   tier at the transport layer as well.
2. It is **opt-in per call**, not automatic. Omitting `required_labels` means no
   check, so the sidecar must set it explicitly — it is not a safety net that applies
   by default.
3. This does **not** remove the need for the sidecar. `required_labels` matches only
   coarse attested labels; it cannot express "this asset, this action, within this
   remaining cap", which is why mandate checks stay off-chain-then-on-chain (§9.5).

---

## S-5 — Caller identity is NOT surfaced to local MCP services

**Gates `attestation.requireChannelBinding`. Answer: keep it `false`.**

`internal/node/gate.go` `HandleMCPStream` is explicit that this is a
*"dumb-pipe proxy"*:

```go
// If the TargetService is for a registered local backend, dumb-pipe proxy to it.
target := reqCtx.Target
...
if ok {
    mcpSvc, isMcp := svc.(*MCPService)
    if isMcp {
        mcpSvc.HandleStreamPassThrough(s)   // raw stream, no caller metadata
        return
    }
}
```

`reqCtx` carries `PeerID`, but it is used only to select the target service and is
then discarded. Confirmed empirically: calling `get-env` on the spawned subprocess
returned **no** `SAM_*`, `PEER_*` or `CALLER_*` variables.

### Consequences for SATM

1. `attestation.requireChannelBinding` **stays `false`** ([§18](../SPECIFICATION.md)).
   There is no second channel to bind to.
2. **The Call Attestation (§6.3.3) is necessary, not defence-in-depth.** It is the
   *only* mechanism by which the inbound sidecar learns who called. Without it, a
   sidecar behind `sam-node` would have to trust a self-asserted caller identity —
   which was exactly the flaw raised in design review (TH-7a).
3. The PLAN S-2 fallback — "move inbound enforcement entirely to the sidecar" — is
   only sound **because** the attestation exists. Worth stating plainly, since the
   fallback would otherwise look like a safe retreat and is not.

---

## 6. Upstream defect: bootstrap enrollment cannot complete

**Severity: blocking for headless enrollment. Found while running S-1.**

`sam-node` and `sam-router` both poll enrollment status with **POST + protobuf body**:

```go
// internal/node/enroll.go
hReq, _ := http.NewRequestWithContext(ctx, "POST", controlPlaneURL+"/enroll/status",
                                      bytes.NewReader(statusData))
hReq.Header.Set("Content-Type", "application/x-protobuf")
```

```go
// internal/router/router.go
statusResp, err := client.Post(r.config.ControlPlaneURL+"/enroll/status",
                               "application/x-protobuf", bytes.NewReader(statusData))
```

The server accepts only **GET with a `peer_id` query parameter**:

```go
// internal/controlplane/server.go, HandleEnrollStatus
if r.Method != http.MethodGet {
    http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    return
}
peerID := r.URL.Query().Get("peer_id")
```

Confirmed against the live server:

| Request | Result |
| --- | --- |
| `GET /enroll/status?peer_id=12D3KooW…` | `200`, 589 bytes of protobuf (the Biscuit) |
| `POST /enroll/status` | `405 Method Not Allowed` |

**Effect:** a node can submit an enrollment and an admin can approve it, but the node
can never retrieve its approved Biscuit. It polls forever:

```
WARN sam-node enroll.go:281 Status check returned status 405 Method Not Allowed
```

So bootstrap-token enrollment — the headless path SATM's devnet and CI depend on — is
non-functional upstream at this commit.

### What we did about it

Patched the **local throwaway build only** (POST → GET) to unblock S-2, S-3 and S-5.
After patching, the router logged `Router bootstrap enrollment approved! Biscuit
received.` and all three nodes came online.

This is **not** a SATM change to SAM and does not contradict
[ADR-0001](adr/0001-integrate-via-control-plane-not-fork.md): the patch lives in a
scratch clone outside the repository, and nothing in `contracts/`, `services/` or
`deploy/` depends on it. It exists so the spikes could answer the questions they were
about, rather than being blocked by an unrelated HTTP-verb bug.

**Actions:**
- [ ] Report upstream to `google/sam` with the reproduction above.
- [ ] Until fixed, the devnet must either carry the same patch or use interactive
      OIDC enrollment. Recorded as risk **R-12** in [PLAN.md](../PLAN.md).

---

## 7. Other observations worth keeping

| Observation | Why it matters |
| --- | --- |
| `--auto-approve-enrollment` **defaults to `false`** | SPECIFICATION §6.1.2 requires manual approval. It is the default, not something to switch on — one less deployment footgun. |
| `--labels` is on `run`, not `join` | The natural guess is wrong; the operator runbook must say so. |
| Nodes default to libp2p `:5001/udp` + `:5002/tcp` | Co-locating nodes on one host requires distinct `--listen`, or peers try to "dial to self". The devnet compose must set these explicitly. |
| Routers need `--allow-loopback` **and** `--external-addr` on a loopback devnet | Without both, the router announces no addresses and nodes fail with "control plane returned no router addresses". |
| `sam-node join` blocks, polling until approved | It also holds an exclusive lock on the data dir, so a second `run` against the same dir fails with a file-lock timeout. |
| Control plane requires `--issuer` even for pure bootstrap-token flows | Hence [`tools/spike/oidc_stub.py`](../tools/spike/oidc_stub.py). SAM's own tests stub the same two endpoints. |

---

## 8. Specification changes made as a result

| Document | Change |
| --- | --- |
| §6.1.3 | Removed the non-existent "primary" label path; declare-then-attest is now described as the mechanism. |
| §10.2 | Upgraded from "verified by source reading" to "verified empirically", and noted that attenuation also gates the service catalogue. |
| §6.3.2 | Notes that `required_labels` gives a genuine second enforcement layer, and that it is opt-in. |
| §6.3.3 | States that the Call Attestation is necessary, not optional, citing S-5. |
| §18 | `attestation.requireChannelBinding` documented as permanently `false` for this SAM version. |
| §19 | OI-1 and OI-2 closed. |
| PLAN §3 | S-1, S-2, S-3, S-5 marked closed with results; risk R-12 added. |
