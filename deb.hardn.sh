#!/bin/bash
# HARDN-XDR - Master Setup Script
# Calls all individual hardening scripts from src/sources/

set -euo pipefail
IFS=$'\n\t'

# Prevent interactive prompts during apt operations in automated/container environments
export DEBIAN_FRONTEND=noninteractive

# Check if running in container environment
if [[ -f /.dockerenv ]] || grep -q "docker\|container" /proc/1/cgroup 2>/dev/null; then
  echo "Detected container environment - individual scripts will handle container-specific logic"
fi

###############################################################################
# Uninstall Option: Remove configuration modifications.
###############################################################################
if [[ "${1:-}" == "-uninstall" ]]; then
  echo "Uninstalling HARDN-XDR to default configurations..."

  # Remove advanced sysctl hardening configuration.
  if [ -f /etc/sysctl.d/99-hardening.conf ]; then
    rm /etc/sysctl.d/99-hardening.conf
    echo "Removed /etc/sysctl.d/99-hardening.conf"
    sysctl --system 2>/dev/null || echo "Warning: Failed to reload sysctl settings."
  fi

  # Remove network protocol blacklisting.
  if [ -f /etc/modprobe.d/disable-net-protocols.conf ]; then
    rm /etc/modprobe.d/disable-net-protocols.conf
    echo "Removed /etc/modprobe.d/disable-net-protocols.conf"
  fi

  echo "Uninstallation complete."
  exit 0
fi

###############################################################################
# Pre-Checks
###############################################################################
# Ensure the script is run as root.
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Please use sudo."
  exit 1
fi

# Secure the script file itself.
chmod 700 "${BASH_SOURCE[0]}"

echo "---------------------------------------------"
echo " HARDN-XDR Master Setup"
echo "---------------------------------------------"

###############################################################################
# Call Individual Hardening Scripts
###############################################################################

# Base path for hardening scripts
SCRIPT_BASE="/sources"

echo "[+] Executing compliance hardening scripts..."
if [ -f "$SCRIPT_BASE/compliance/openscap-registry.sh" ]; then
    echo "  - Running OpenSCAP compliance checks..."
    bash "$SCRIPT_BASE/compliance/openscap-registry.sh"
else
    echo "  - Warning: OpenSCAP script not found"
fi

echo "[+] Executing memory protection scripts..."
if [ -f "$SCRIPT_BASE/memory/clamav-registry.sh" ]; then
    echo "  - Running ClamAV configuration..."
    bash "$SCRIPT_BASE/memory/clamav-registry.sh"
else
    echo "  - Warning: ClamAV script not found"
fi

if [ -f "$SCRIPT_BASE/memory/protection.sh" ]; then
    echo "  - Running memory protection setup..."
    bash "$SCRIPT_BASE/memory/protection.sh"
else
    echo "  - Warning: Memory protection script not found"
fi

echo "[+] Executing network security scripts..."
if [ -f "$SCRIPT_BASE/network/aide-registry.sh" ]; then
    echo "  - Running AIDE integrity monitoring..."
    source "$SCRIPT_BASE/network/aide-registry.sh"
    initialize_minimal_aide 2>/dev/null || echo "    AIDE setup completed with warnings"
else
    echo "  - Warning: AIDE script not found"
fi

if [ -f "$SCRIPT_BASE/network/security.sh" ]; then
    echo "  - Running network security configuration..."
    bash "$SCRIPT_BASE/network/security.sh"
else
    echo "  - Warning: Network security script not found"
fi

if [ -f "$SCRIPT_BASE/network/tripwire-registry.sh" ]; then
    echo "  - Running Tripwire configuration..."
    bash "$SCRIPT_BASE/network/tripwire-registry.sh"
else
    echo "  - Warning: Tripwire script not found"
fi

echo "[+] Executing privilege management scripts..."
if [ -f "$SCRIPT_BASE/privilege/access.sh" ]; then
    echo "  - Running privilege access controls..."
    bash "$SCRIPT_BASE/privilege/access.sh"
else
    echo "  - Warning: Privilege access script not found"
fi

if [ -f "$SCRIPT_BASE/privilege/rkhunter-registry.sh" ]; then
    echo "  - Running rkhunter configuration..."
    bash "$SCRIPT_BASE/privilege/rkhunter-registry.sh"
else
    echo "  - Warning: rkhunter script not found"
fi

echo "[+] Executing security integrity scripts..."
if [ -f "$SCRIPT_BASE/security/integrity.sh" ]; then
    echo "  - Running security integrity checks..."
    bash "$SCRIPT_BASE/security/integrity.sh"
else
    echo "  - Warning: Security integrity script not found"
fi

echo ""
echo "---------------------------------------------"
echo " HARDN-XDR Setup Complete"
echo "---------------------------------------------"
echo "All hardening scripts have been executed."
echo "Review the output above for any warnings or errors."
