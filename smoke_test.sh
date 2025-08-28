#!/bin/bash
set -Eeuo pipefail


command -v openssl >/dev/null || { echo "openssl missing"; exit 1; }
command -v oscap   >/dev/null || { echo "openscap missing"; exit 1; }
command -v aide    >/dev/null || { echo "aide missing"; exit 1; }


if command -v update-crypto-policies >/dev/null 2>&1; then
  CURRENT=$(update-crypto-policies --show 2>/dev/null || echo "unknown")
  [[ "$CURRENT" == "FIPS" ]] || echo "WARN: crypto policy not FIPS (got: $CURRENT)"
fi

echo "smoke: OK"
