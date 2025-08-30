#!/bin/bash

set -Eeuo pipefail
umask 027

echo "=== Entrypoint started ==="
echo "Current user: $(id)"
echo "Working directory: $(pwd)"
echo "Arguments: $*"
echo "Environment: $(env | grep -E '(PATH|HOME|USER|SHELL)' | sort)"

# Debug: Check if required directories exist
echo "Checking required directories..."
for dir in /opt/hardn-xdr /sources /usr/local/bin; do
    if [[ -d "$dir" ]]; then
        echo "✓ Directory exists: $dir"
        ls -la "$dir" | head -3
    else
        echo "✗ Directory missing: $dir"
    fi
done

# Debug: Check if required files exist
echo "Checking required files..."
for file in /usr/local/bin/deb.hardn.sh /usr/local/bin/entrypoint.sh; do
    if [[ -f "$file" ]]; then
        echo "✓ File exists: $file"
        ls -la "$file"
    else
        echo "✗ File missing: $file"
    fi
done

if [[ "$(id -u)" -eq 0 ]]; then
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
  
  mkdir -p /home/hardn
  chown hardn:hardn /home/hardn
  chmod 755 /home/hardn
  
  mkdir -p /var/lib/hardn
  chown -R hardn:hardn /var/lib/hardn
  chmod 755 /var/lib/hardn
  
  STATE_DIR="/opt/hardn-xdr/state"
  mkdir -p "$STATE_DIR"
  chown -R hardn:hardn "$STATE_DIR"
  chmod 755 "$STATE_DIR"
  
  echo "Switching to hardn user..."
  exec su - hardn -c "cd /opt/hardn-xdr && exec \"\$@\"" -- "${@:-while true; do sleep 30; done}"
else
  echo "Running as non-root user, executing command..."
  exec "${@:-while true; do sleep 30; done}"
fi