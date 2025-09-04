#!/bin/bash
set -Eeuo pipefail
umask 027

echo "=== Entrypoint started ==="
echo "Current user: $(id)"
echo "Working directory: $(pwd)"
echo "Arguments count: $#"
echo "Environment: $(env | grep -E '(PATH|HOME|USER|SHELL)' | sort)"

echo "Checking required directories..."
for dir in /opt/hardn-xdr /sources /usr/local/bin; do
  if [[ -d "$dir" ]]; then
    echo "✓ $dir"
  else
    echo "✗ $dir (missing)"
  fi
done

echo "Checking required files..."
for file in /usr/local/bin/deb.hardn.sh /usr/local/bin/entrypoint.sh; do
  [[ -f "$file" ]] && echo "✓ $file" || echo "✗ $file (missing)"
done

# Decide what command to run
if [[ $# -gt 0 ]]; then
  TARGET_CMD=("$@")
else
  TARGET_CMD=(/bin/sh -c 'while true; do sleep 30; done')
fi
echo "Resolved command: ${TARGET_CMD[*]}"

if [[ "$(id -u)" -eq 0 ]]; then
  # One-time hardening during first root start
  if [[ ! -f /opt/hardn-xdr/.hardening_complete ]]; then
    echo "Running hardening script as root..."
    if /usr/local/bin/deb.hardn.sh; then
      echo "Hardening script completed successfully"
    else
      echo "WARN: Hardening script returned non-zero (continuing)"
    fi
    touch /opt/hardn-xdr/.hardening_complete
  else
    echo "Hardening already completed, skipping."
  fi

  # Ensure user and dirs
  useradd -m -u 10001 -s /bin/bash hardn 2>/dev/null || true
  install -d -o hardn -g hardn -m 0755 /home/hardn /var/lib/hardn /opt/hardn-xdr/state

  # Drop privileges correctly:
  # su runs /bin/sh -c '...' where $0 and $@ come from args after '--'
  echo "Switching to user 'hardn' and execing command…"
  exec su -s /bin/sh -c 'cd /opt/hardn-xdr && exec "$0" "$@"' hardn -- "${TARGET_CMD[@]}"
else
  echo "Running as non-root, execing command…"
  exec "${TARGET_CMD[@]}"
fi