#!/bin/bash
set -Eeuo pipefail
umask 027

log() { printf '[entrypoint] %s\n' "$*"; }

log "started"
log "uid=$(id -u) gid=$(id -g) user=$(id -un)"
log "pwd=$(pwd)"
log "args($#): ${*:-<none>}"
env | grep -E '^(PATH|HOME|USER|SHELL)=' | sort | sed 's/^/[env] /' || true

# Resolve target command (don’t let empty $@ kill the shell)
if [[ $# -gt 0 ]]; then
  TARGET_CMD=("$@")
else
  # benign default so CI “startup strategy” won’t exit immediately
  TARGET_CMD=(/bin/sh -c 'while true; do sleep 30; done')
fi
log "resolved command: ${TARGET_CMD[*]}"

# Minimal presence checks (won’t fail startup)
for d in /opt/hardn-xdr /usr/local/bin; do
  [[ -d "$d" ]] && log "dir ok: $d" || log "dir missing: $d"
done
for f in /usr/local/bin/deb.hardn.sh /usr/local/bin/entrypoint.sh; do
  [[ -f "$f" ]] && log "file ok: $f" || log "file missing: $f"
done

# === Option B logic ===
# If we are NOT root, skip hardening and user/perm work.
if [[ "$(id -u)" -ne 0 ]]; then
  log "non-root detected; skipping hardening and privilege drop"
  exec "${TARGET_CMD[@]}"
fi

# Root path: do one-time hardening, then drop to 'hardn' if present
log "root detected; performing one-time hardening if needed"

if [[ ! -f /opt/hardn-xdr/.hardening_complete ]]; then
  if /usr/local/bin/deb.hardn.sh; then
    log "hardening completed successfully"
  else
    log "WARNING: hardening returned non-zero; continuing"
  fi
  touch /opt/hardn-xdr/.hardening_complete || true
fi

# Ensure runtime dirs (idempotent)
install -d -m 0755 /opt/hardn-xdr/state /var/lib/hardn /home/hardn || true

# Ensure the 'hardn' user exists (idempotent)
if ! id -u hardn >/dev/null 2>&1; then
  useradd -m -u 10001 -s /bin/bash hardn || true
fi

# Set ownership where it’s safe
chown -R hardn:hardn /opt/hardn-xdr /var/lib/hardn /home/hardn || true

# Drop privileges correctly:
# With `sh -c`, $0 is the first arg after `--` and $@ are the rest.
log "dropping privileges to 'hardn' and execing command"
exec su -s /bin/sh -c 'cd /opt/hardn-xdr && exec "$0" "$@"' hardn -- "${TARGET_CMD[@]}"