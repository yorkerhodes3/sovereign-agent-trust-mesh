# Spike harness

Throwaway tooling used to run the Phase 1 spikes against a **real** SAM mesh.
Results: [../../docs/SPIKE-FINDINGS.md](../../docs/SPIKE-FINDINGS.md).

Kept in the repository because the spikes are re-runnable and their conclusions
are load-bearing: if a future SAM release changes how attenuation evaluates
caller labels, S-2 should be re-run rather than re-argued.

## Contents

| File | Purpose |
| --- | --- |
| `oidc_stub.py` | Minimal OIDC discovery + JWKS. `sam-control-plane` refuses to start without `--issuer` even when every node uses a bootstrap token and no OIDC token is ever verified. SAM's own tests stub the same two endpoints. |

## Reproducing the spikes

Requires Go 1.25+ (to build SAM) and Python 3.12. No Docker.

```bash
# 1. Build SAM from source
git clone --depth 1 https://github.com/google/sam.git
cd sam
go build -o bin/sam-control-plane ./cmd/sam-control-plane
go build -o bin/sam-router        ./cmd/sam-router
go build -o bin/sam-node          ./cmd/sam-node
go build -o bin/mcp-client        ./cmd/mcp-client

# 2. Stub issuer
python tools/spike/oidc_stub.py --port 5570 &

# 3. Control plane (manual approval is already the DEFAULT)
./bin/sam-control-plane \
  --bind-address 127.0.0.1:8090 \
  --issuer http://127.0.0.1:5570 \
  --allowed-audiences satm-spike \
  --admin-token-path ./admin-token \
  --db-dsn ./cp.db
```

### Gotchas that cost time

Each of these was discovered the hard way; they are why the devnet compose file
now sets what it sets.

1. **`--labels` is on `run`, not `join`.** Enrolling via `join` gives you a node
   with no declared labels and no obvious reason why.
2. **A router on loopback needs BOTH `--allow-loopback` and `--external-addr`.**
   With neither, it registers but announces `ListenAddrs: []`, and every node
   then fails with `control plane returned no router addresses` — which does not
   point at the router.
3. **Co-located nodes need distinct libp2p `--listen` ports.** They all default
   to `:5001/udp` + `:5002/tcp`, so the second and third nodes try to "dial to
   self".
4. **`sam-node join` blocks and holds an exclusive data-dir lock.** A later `run`
   against the same directory dies with a file-lock timeout.
5. **Bootstrap enrollment is broken upstream** — see
   [SPIKE-FINDINGS.md §6](../../docs/SPIKE-FINDINGS.md). Clients POST to
   `/enroll/status`; the server accepts only `GET` with a `peer_id` query param,
   so a node never collects its approved Biscuit. Reproduce with:

   ```bash
   curl -i "http://127.0.0.1:8090/enroll/status?peer_id=12D3KooW..."   # 200
   curl -i -X POST "http://127.0.0.1:8090/enroll/status"                # 405
   ```

   A one-line client change (POST → GET) unblocks it. That patch was applied to a
   **scratch clone only** — SATM does not fork SAM
   ([ADR-0001](../../docs/adr/0001-integrate-via-control-plane-not-fork.md)), and
   nothing in this repository depends on it.
