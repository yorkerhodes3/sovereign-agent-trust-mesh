#!/usr/bin/env python3
"""
Minimal OIDC discovery stub for the SATM Phase 1 spike harness.

`sam-control-plane` refuses to start without `--issuer`, even when every node
enrolls with a bootstrap token and no OIDC token is ever verified. It only needs
the discovery document and a JWKS to construct its verifier at boot.

This serves exactly those two endpoints and nothing else. SAM's own unit tests
stub the same two (internal/controlplane/server_test.go), so this is the
sanctioned shape rather than an invention.

SPIKE HARNESS ONLY. Not a real identity provider: it issues no tokens, verifies
nothing, and must never be used outside a throwaway local mesh.

Usage:
    python oidc_stub.py [--port 5570]
"""

import argparse
import base64
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

# A throwaway RSA public key. Only its *shape* matters: the control plane parses
# the JWKS at boot and never uses it, because bootstrap-token enrollment does not
# involve OIDC token verification.
_MODULUS = int(
    "00a2b3c4d5e6f7081920a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6"
    "0718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6"
    "0718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6"
    "0718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f7",
    16,
)
_EXPONENT = 65537


def _b64u(i: int) -> str:
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class OidcStubHandler(BaseHTTPRequestHandler):
    issuer = "http://127.0.0.1:5570"

    def _json(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802  (stdlib naming)
        if self.path.startswith("/.well-known/openid-configuration"):
            self._json(
                {
                    "issuer": self.issuer,
                    "jwks_uri": f"{self.issuer}/keys",
                    "authorization_endpoint": f"{self.issuer}/auth",
                    "token_endpoint": f"{self.issuer}/token",
                    "device_authorization_endpoint": f"{self.issuer}/device",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }
            )
        elif self.path.startswith("/keys"):
            self._json(
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "alg": "RS256",
                            "use": "sig",
                            "kid": "satm-spike-key",
                            "n": _b64u(_MODULUS),
                            "e": _b64u(_EXPONENT),
                        }
                    ]
                }
            )
        else:
            self.send_error(404, "spike stub serves only discovery and JWKS")

    def log_message(self, fmt: str, *args) -> None:
        logging.debug("oidc-stub %s", fmt % args)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5570)
    args = parser.parse_args()

    OidcStubHandler.issuer = f"http://127.0.0.1:{args.port}"
    server = HTTPServer(("127.0.0.1", args.port), OidcStubHandler)
    print(f"oidc stub listening on {OidcStubHandler.issuer}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
