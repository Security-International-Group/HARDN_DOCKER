#!/bin/bash
set -Eeuo pipefail


command -v openssl >/dev/null || { echo "openssl missing"; exit 1; }
command -v oscap   >/dev/null || { echo "openscap missing - STIG scans will be skipped"; }
command -v aide    >/dev/null || { echo "aide missing - file integrity checks will be skipped"; }

if command -v update-crypto-policies >/dev/null 2>&1; then
  CURRENT=$(update-crypto-policies --show 2>/dev/null || echo "unknown")
  [[ "$CURRENT" == "FIPS" ]] || echo "WARN: crypto policy not FIPS (got: $CURRENT)"
fi

echo "smoke: OK"
