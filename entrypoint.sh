#!/bin/bash
set -Eeuo pipefail
umask 027


if [[ "$(id -u)" -eq 0 ]]; then
  /usr/local/bin/rhel.hardn.sh || echo "WARN: hardening script completed with warnings"
  install -d -o hardn -g hardn /opt/hardn-xdr/state
  exec su -s /bin/bash -c "$*" hardn
fi


if [[ $# -eq 0 ]]; then
  tail -f /dev/null
else
  exec "$@"
fi