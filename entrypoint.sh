#!/bin/bash

set -Eeuo pipefail
umask 027

echo "=== Entrypoint started ==="
echo "Current user: $(id)"
echo "Working directory: $(pwd)"
echo "Arguments: $*"

if [[ "$(id -u)" -eq 0 ]]; then
  # Check if hardening was already completed during build
  if [ -f "/opt/hardn-xdr/.hardening_complete" ]; then
    echo "Hardening already completed during build, skipping..."
  else
    echo "Running as root, executing hardening script..."
    if /usr/local/bin/deb.hardn.sh; then
      echo "Hardening script completed successfully"
      touch /opt/hardn-xdr/.hardening_complete
    else
      echo "WARN: Hardening script completed with warnings/errors, continuing..."
      touch /opt/hardn-xdr/.hardening_complete
    fi
  fi
  
  STATE_DIR="${HARDN_XDR_HOME:-/opt/hardn-xdr}/state"
  echo "Creating state directory: $STATE_DIR"
  if ! install -d -o hardn -g hardn "$STATE_DIR" 2>/dev/null; then
    if install -d -o hardn -g hardn /run/hardn-xdr/state 2>/dev/null; then
      STATE_DIR=/run/hardn-xdr/state
    else
      install -d -o hardn -g hardn /tmp/hardn-xdr/state 2>/dev/null || true
      STATE_DIR=/tmp/hardn-xdr/state
    fi
    echo "INFO: using STATE_DIR=$STATE_DIR"
  fi
  
  echo "Switching to hardn user..."
  # Try bash first, fall back to sh
  if command -v bash >/dev/null 2>&1; then
    SHELL_CMD="/bin/bash"
  else
    SHELL_CMD="/bin/sh"
  fi
  
  # Use exec to replace the current process with su
  if exec su -s "$SHELL_CMD" -c "${*:-while true; do sleep 30; done}" hardn 2>/dev/null; then
    echo "Successfully switched to hardn user"
  else
    echo "ERROR: Failed to switch to hardn user, staying as root"
    exec "${@:-while true; do sleep 30; done}"
  fi
fi

echo "Running as non-root user, executing command..."
exec "${@:-while true; do sleep 30; done}"