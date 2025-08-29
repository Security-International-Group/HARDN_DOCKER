#!/bin/bash

set -Eeuo pipefail
umask 027

if [[ "$(id -u)" -eq 0 ]]; then
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
  exec su -s /bin/bash -c "${*:-tail -f /dev/null}" hardn
fi
exec "${@:-tail -f /dev/null}"