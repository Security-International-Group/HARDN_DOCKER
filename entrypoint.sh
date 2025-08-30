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
  
  # Try to use su-exec or gosu if available (better for containers)
  if command -v su-exec >/dev/null 2>&1; then
    echo "Using su-exec to switch user..."
    exec su-exec hardn "${@:-while true; do sleep 30; done}"
  elif command -v gosu >/dev/null 2>&1; then
    echo "Using gosu to switch user..."
    exec gosu hardn "${@:-while true; do sleep 30; done}"
  else
    # Fallback to su with proper environment
    echo "Using su to switch user..."
    # Create a simple wrapper script in a location accessible to hardn user
    WRAPPER_DIR="/home/hardn"
    WRAPPER_SCRIPT="$WRAPPER_DIR/cmd_wrapper.sh"
    
    # Ensure the directory exists and has proper permissions
    mkdir -p "$WRAPPER_DIR" 2>/dev/null || true
    chown hardn:hardn "$WRAPPER_DIR" 2>/dev/null || true
    
    # Create wrapper script with proper permissions
    cat > "$WRAPPER_SCRIPT" << 'EOF'
#!/bin/bash
exec "$@"
EOF
    chmod 755 "$WRAPPER_SCRIPT"
    chown hardn:hardn "$WRAPPER_SCRIPT" 2>/dev/null || true
    
    # Try to execute as hardn user
    if su -c "$WRAPPER_SCRIPT $*" hardn 2>/dev/null; then
      echo "Successfully executed command as hardn user"
      exit 0  # Exit successfully if hardn user execution worked
    else
      echo "ERROR: Failed to execute as hardn user, running as root"
      # Execute the command as root
      exec "${@:-while true; do sleep 30; done}"
    fi
  fi
else
  echo "Running as non-root user, executing command..."
  exec "${@:-while true; do sleep 30; done}"
fi