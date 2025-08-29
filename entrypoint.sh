#!/bin/bash

set -Eeuo pipefail
umask 027

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Running as root, executing hardening script..."
  /usr/local/bin/deb.hardn.sh || echo "WARN: hardening script completed with warnings"
  
  STATE_DIR="${HARDN_XDR_HOME:-/opt/hardn-xdr}/state"
  if ! install -d -o hardn -g hardn "$STATE_DIR"; then
    if install -d -o hardn -g hardn /run/hardn-xdr/state 2>/dev/null; then
      STATE_DIR=/run/hardn-xdr/state
    else
      install -d -o hardn -g hardn /tmp/hardn-xdr/state || true
      STATE_DIR=/tmp/hardn-xdr/state
    fi
    echo "INFO: using STATE_DIR=$STATE_DIR"
  fi
  
  echo "Switching to hardn user..."
  # Use exec to replace the current process with su
  if ! exec su -s /bin/bash -c "${*:-tail -f /dev/null}" hardn; then
    echo "ERROR: Failed to switch to hardn user, staying as root"
    exec "${@:-tail -f /dev/null}"
  fi
fi

echo "Running as non-root user, executing command..."
exec "${@:-tail -f /dev/null}"