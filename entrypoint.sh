#!/bin/bash

set -Eeuo pipefail
umask 027

log() { printf '[entrypoint] %s\n' "$*"; }

log "started"
log "uid=$(id -u) gid=$(id -g) user=$(id -un)"
log "pwd=$(pwd)"
log "args($#): ${*:-<none>}"
env | grep -E '^(PATH|HOME|USER|SHELL)=' | sort | sed 's/^/[env] /' || true

if [[ $# -gt 0 ]]; then
  TARGET_CMD=("$@")
else
  TARGET_CMD=(/bin/sh -c 'while true; do sleep 30; done')
fi
log "resolved command: ${TARGET_CMD[*]}"

for d in /opt/hardn-xdr /usr/local/bin; do
  [[ -d "$d" ]] && log "dir ok: $d" || log "dir missing: $d"
done
for f in /usr/local/bin/deb.hardn.sh /usr/local/bin/entrypoint.sh; do
  [[ -f "$f" ]] && log "file ok: $f" || log "file missing: $f"
done

# -------- Non-root path  --------
if [[ "$(id -u)" -ne 0 ]]; then
  log "non-root detected; skipping hardening and user/perm work"
  exec "${TARGET_CMD[@]}"
fi

# -------- Root path (local admin/test runs) --------
log "root detected; performing one-time hardening if needed"

# The entrypoint is now simplified to only run the hardening script
# and then exec the command. Privilege dropping is handled by docker-compose.
if [[ ! -f /opt/hardn-xdr/.hardening_complete ]]; then
  if [[ -x /usr/local/bin/deb.hardn.sh ]]; then
    if /usr/local/bin/deb.hardn.sh; then
      log "hardening completed successfully"
    else
      log "WARNING: hardening returned non-zero; continuing"
    fi
  else
    log "WARNING: /usr/local/bin/deb.hardn.sh not present/executable; skipping"
  fi
  # Create a marker file to show hardening has run
  : > /opt/hardn-xdr/.hardening_complete || true
fi

# Directly execute the command.
# The container should be started with the correct user via docker-compose.
log "executing command: ${TARGET_CMD[*]}"
exec "${TARGET_CMD[@]}"
