#!/bin/bash

set -Eeuo pipefail
umask 027

log() { printf '[entrypoint] %s\n' "$*"; }

log "started"
log "uid=$(id -u) gid=$(id -g) user=$(id -un)"
log "pwd=$(pwd)"
log "args($#): ${*:-<none>}"
env | grep -E '^(PATH|HOME|USER|SHELL)=' | sort | sed 's/^/[env] /' || true

# Ensure we always have *some* command (prevents empty exec)
if [[ $# -gt 0 ]]; then
  TARGET_CMD=("$@")
else
  TARGET_CMD=(/bin/sh -c 'while true; do sleep 30; done')
fi
log "resolved command: ${TARGET_CMD[*]}"

# Light checks; never fail startup
for d in /opt/hardn-xdr /usr/local/bin; do
  [[ -d "$d" ]] && log "dir ok: $d" || log "dir missing: $d"
done
for f in /usr/local/bin/deb.hardn.sh /usr/local/bin/entrypoint.sh; do
  [[ -f "$f" ]] && log "file ok: $f" || log "file missing: $f"
done

# -------- Non-root path (CI default) --------
if [[ "$(id -u)" -ne 0 ]]; then
  log "non-root detected; skipping hardening and user/perm work"
  exec "${TARGET_CMD[@]}"
fi

# -------- Root path (local admin/test runs) --------
log "root detected; performing one-time hardening if needed"

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
  : > /opt/hardn-xdr/.hardening_complete || true
fi

# Ensure runtime dirs (idempotent)
install -d -m 0755 /opt/hardn-xdr/state /var/lib/hardn /home/hardn || true

# Ensure the 'hardn' user exists (idempotent)
if ! id -u hardn >/dev/null 2>&1; then
  # shell defaults to nologin in your Dockerfile; we'll override with -s when we switch
  useradd -m -u 10001 -s /usr/sbin/nologin hardn || true
fi

# Ownership (best-effort)
chown -R hardn:hardn /opt/hardn-xdr /var/lib/hardn /home/hardn || true

# Drop privileges. Override shell to /bin/sh for the exec, and forward args safely.
# Note: with sh -lc, $0 is the first arg after '--', and $@ are the rest.
log "dropping privileges to 'hardn' and execing"
if command -v runuser >/dev/null 2>&1; then
  exec runuser -u hardn -- /bin/sh -lc 'cd /opt/hardn-xdr && exec "$0" "$@"' -- "${TARGET_CMD[@]}"
else
  # Fallback to su (util-linux). Use -s /bin/sh to bypass nologin shell.
  exec su -s /bin/sh -c 'cd /opt/hardn-xdr && exec "$0" "$@"' hardn -- "${TARGET_CMD[@]}"
fi