#!/usr/bin/env bash
# Verify the vendored ERC-8004 sources are byte-identical to the pinned upstream
# commit. vendor/ must mirror upstream exactly; SATM changes belong in src/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/contracts/vendor/erc8004"
UPSTREAM_FILE="$VENDOR/UPSTREAM"

if [[ ! -f "$UPSTREAM_FILE" ]]; then
  echo "error: $UPSTREAM_FILE not found" >&2
  exit 1
fi

SHA="$(sed -n 's/^commit:[[:space:]]*//p' "$UPSTREAM_FILE" | head -1)"
if [[ -z "$SHA" ]]; then
  echo "error: no 'commit:' line in $UPSTREAM_FILE" >&2
  exit 1
fi

echo "pinned upstream commit: $SHA"

FILES=(
  IdentityRegistryUpgradeable
  ReputationRegistryUpgradeable
  ValidationRegistryUpgradeable
  ERC1967Proxy
  MinimalUUPS
)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
for f in "${FILES[@]}"; do
  url="https://raw.githubusercontent.com/erc-8004/erc-8004-contracts/$SHA/contracts/$f.sol"
  if ! curl -sSfL "$url" -o "$tmp/$f.sol"; then
    echo "  FETCH-FAIL  $f.sol" >&2
    fail=1
    continue
  fi
  if diff -q "$tmp/$f.sol" "$VENDOR/$f.sol" >/dev/null 2>&1; then
    echo "  ok          $f.sol"
  else
    echo "  MODIFIED    $f.sol" >&2
    diff -u "$tmp/$f.sol" "$VENDOR/$f.sol" >&2 || true
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  echo >&2
  echo "vendor/erc8004 has diverged from the pinned commit." >&2
  echo "Put SATM-specific changes in contracts/src/, not in vendor/." >&2
  exit 1
fi

echo "all vendored sources match upstream"
