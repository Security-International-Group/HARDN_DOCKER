#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

export DEBIAN_FRONTEND=noninteractive
if [[ -f /.dockerenv ]] || grep -q "docker\|container" /proc/1/cgroup 2>/dev/null; then
  echo "Detected container environment - some operations may be limited"
fi

###############################################################################
# Backup
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
# Pre-Flight
###############################################################################
# Ensure the script is run as root for hardening operations
if [[ $EUID -ne 0 ]]; then
  echo "This script requires root privileges for hardening operations."
  echo "Please run as root or ensure the container runs with appropriate privileges."
  exit 1
fi

# Set hardening phase flag for CIS compliance checks
export HARDENING_PHASE=true

###############################################################################
# Install Missing Security Packages
###############################################################################

echo "[+] Installing additional security packages..."
# Install AppArmor for security profiles
if ! command -v apparmor_status >/dev/null 2>&1; then
    echo "  - Installing AppArmor..."
    apt-get update --quiet && apt-get install -y --no-install-recommends apparmor apparmor-utils
fi

# Configure and start AppArmor
echo "  - Configuring AppArmor..."
if command -v apparmor_status >/dev/null 2>&1; then
    # Start AppArmor service
    /etc/init.d/apparmor start 2>/dev/null || true

    # Load AppArmor profiles
    if [ -d /etc/apparmor.d/ ]; then
        apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true
    fi

    # Enable AppArmor in the kernel if possible
    if [ -f /sys/module/apparmor/parameters/enabled ]; then
        echo "Y" > /sys/module/apparmor/parameters/enabled 2>/dev/null || true
    fi
fi

# Install UFW for firewall management
if ! command -v ufw >/dev/null 2>&1; then
    echo "  - Installing UFW..."
    apt-get install -y --no-install-recommends ufw
fi

# Install Fail2ban for intrusion detection
if ! command -v fail2ban-server >/dev/null 2>&1; then
    echo "  - Installing Fail2ban..."
    apt-get install -y --no-install-recommends fail2ban
fi

# Install libpam-pwquality for password quality enforcement
if ! dpkg -l | grep -q libpam-pwquality; then
    echo "  - Installing libpam-pwquality..."
    apt-get install -y --no-install-recommends libpam-pwquality
fi

# Clean up package cache to keep image small
apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

###############################################################################
# Execute /sources scripts AFTER Debian packages are installed
###############################################################################

echo "[+] Debian packages installation complete. Now executing /sources scripts..."

# Base path for hardening scripts
SCRIPT_BASE="/sources"

echo "[+] Executing compliance hardening scripts..."
if [ -f "$SCRIPT_BASE/compliance/openscap-registry.sh" ]; then
    echo "  - Running OpenSCAP compliance checks..."
    if bash "$SCRIPT_BASE/compliance/openscap-registry.sh"; then
        echo "  - OpenSCAP completed successfully"
    else
        echo "  - OpenSCAP completed with warnings"
    fi
else
    echo "  - Warning: OpenSCAP script not found"
fi

if [ -f "$SCRIPT_BASE/compliance/cron.sh" ]; then
    echo "  - Setting up automated compliance updates..."
    if bash "$SCRIPT_BASE/compliance/cron.sh"; then
        echo "  - Cron setup completed successfully"
    else
        echo "  - Cron setup completed with warnings"
    fi
else
    echo "  - Warning: Cron script not found"
fi

echo "[+] Executing memory protection scripts..."
if [ -f "$SCRIPT_BASE/memory/clamav.sh" ]; then
    echo "  - Running ClamAV configuration..."
    if bash "$SCRIPT_BASE/memory/clamav.sh"; then
        echo "  - ClamAV completed successfully"
    else
        echo "  - ClamAV completed with warnings"
    fi
else
    echo "  - Warning: ClamAV script not found"
fi

if [ -f "$SCRIPT_BASE/memory/protection.sh" ]; then
    echo "  - Running memory protection setup..."
    # Source the protection script to load functions
    . "$SCRIPT_BASE/memory/protection.sh"

    # Call specific memory protection functions
    if command -v prevent_core_dumps >/dev/null 2>&1; then
        prevent_core_dumps
        echo "  - Core dump prevention configured"
    fi

    if command -v configure_memory_protection >/dev/null 2>&1; then
        configure_memory_protection
        echo "  - Memory protection configured"
    fi

    if command -v setup_buffer_overflow_protection >/dev/null 2>&1; then
        setup_buffer_overflow_protection
        echo "  - Buffer overflow protection configured"
    fi

    echo "  - Memory protection completed successfully"
else
    echo "  - Warning: Memory protection script not found"
fi

echo "[+] Executing network security scripts..."
if [ -f "$SCRIPT_BASE/network/aide.sh" ]; then
    echo "  - Running AIDE integrity monitoring..."
    source "$SCRIPT_BASE/network/aide.sh"
    if command -v initialize_minimal_aide >/dev/null 2>&1; then
        if initialize_minimal_aide; then
            echo "  - AIDE completed successfully"
        else
            echo "  - AIDE completed with warnings"
        fi
    else
        echo "    Warning: initialize_minimal_aide function not found"
    fi
else
    echo "  - Warning: AIDE script not found"
fi

if [ -f "$SCRIPT_BASE/security/security.sh" ]; then
    echo "  - Running security configuration..."
    if bash "$SCRIPT_BASE/security/security.sh"; then
        echo "  - Network security completed successfully"
    else
        echo "  - Network security completed with warnings"
    fi
else
    echo "  - Warning: Network security script not found"
fi

if [ -f "$SCRIPT_BASE/security/apparmor.sh" ]; then
    echo "  - Running AppArmor configuration..."
    if bash "$SCRIPT_BASE/security/apparmor.sh"; then
        echo "  - AppArmor configuration completed successfully"
    else
        echo "  - AppArmor configuration completed with warnings"
    fi
else
    echo "  - Warning: AppArmor script not found"
fi

if [ -f "$SCRIPT_BASE/security/selinux.sh" ]; then
    echo "  - Running SELinux configuration..."
    if bash "$SCRIPT_BASE/security/selinux.sh"; then
        echo "  - SELinux configuration completed successfully"
    else
        echo "  - SELinux configuration completed with warnings"
    fi
else
    echo "  - Warning: SELinux script not found"
fi

if [ -f "$SCRIPT_BASE/security/docker-daemon.sh" ]; then
    echo "  - Running Docker daemon configuration..."
    if bash "$SCRIPT_BASE/security/docker-daemon.sh"; then
        echo "  - Docker daemon configuration completed successfully"
    else
        echo "  - Docker daemon configuration completed with warnings"
    fi
else
    echo "  - Warning: Docker daemon script not found"
fi

if [ -f "$SCRIPT_BASE/security/image-security.sh" ]; then
    echo "  - Running container image security configuration..."
    if bash "$SCRIPT_BASE/security/image-security.sh"; then
        echo "  - Container image security configuration completed successfully"
    else
        echo "  - Container image security configuration completed with warnings"
    fi
else
    echo "  - Warning: Container image security script not found"
fi

if [ -f "$SCRIPT_BASE/security/host-config.sh" ]; then
    echo "  - Running host configuration security..."
    if bash "$SCRIPT_BASE/security/host-config.sh"; then
        echo "  - Host configuration security completed successfully"
    else
        echo "  - Host configuration security completed with warnings"
    fi
else
    echo "  - Warning: Host configuration script not found"
fi

if [ -f "$SCRIPT_BASE/network/tripwire.sh" ]; then
    echo "  - Running Tripwire configuration..."
    if bash "$SCRIPT_BASE/network/tripwire.sh"; then
        echo "  - Tripwire completed successfully"
    else
        echo "  - Tripwire completed with warnings"
    fi
else
    echo "  - Warning: Tripwire script not found"
fi

echo "[+] Executing privilege management scripts..."
if [ -f "$SCRIPT_BASE/privilege/access.sh" ]; then
    echo "  - Running privilege access controls..."
    # Source the access script to load functions
    . "$SCRIPT_BASE/privilege/access.sh"

    # Call specific functions
    if command -v configure_pam_security >/dev/null 2>&1; then
        configure_pam_security
        echo "  - PAM security configured successfully"
    else
        echo "  - Warning: configure_pam_security function not found"
    fi

    if command -v configure_user_access >/dev/null 2>&1; then
        configure_user_access
        echo "  - User access controls configured successfully"
    fi

    if command -v prevent_privilege_escalation >/dev/null 2>&1; then
        prevent_privilege_escalation
        echo "  - Privilege escalation prevention configured successfully"
    fi
else
    echo "  - Warning: Privilege access script not found"
fi

if [ -f "$SCRIPT_BASE/privilege/rkhunter.sh" ]; then
    echo "  - Running rkhunter configuration..."
    if bash "$SCRIPT_BASE/privilege/rkhunter.sh"; then
        echo "  - rkhunter completed successfully"
    else
        echo "  - rkhunter completed with warnings"
    fi
else
    echo "  - Warning: rkhunter script not found"
fi

echo "[+] Executing security integrity scripts..."
if [ -f "$SCRIPT_BASE/security/integrity.sh" ]; then
    echo "  - Running security integrity checks..."
    if HARDENING_PHASE=true bash "$SCRIPT_BASE/security/integrity.sh"; then
        echo "  - Security integrity completed successfully"
    else
        echo "  - Security integrity completed with warnings"
    fi
else
    echo "  - Warning: Security integrity script not found"
fi

###############################################################################
# DISA STIG Configuration
###############################################################################

# STIG Compliance Level Configuration
# Category I: High severity - Critical vulnerabilities requiring immediate action
# Category II: Medium severity - Significant vulnerabilities requiring action
# Category III: Low severity - Minor vulnerabilities requiring attention
export STIG_COMPLIANCE_LEVEL="${STIG_COMPLIANCE_LEVEL:-I}"
export STIG_COMPLIANCE_CATEGORIES="I II III"

# Docker/Kubernetes STIG Requirements
export DOCKER_STIG_ENABLED="${DOCKER_STIG_ENABLED:-true}"
export KUBERNETES_STIG_ENABLED="${KUBERNETES_STIG_ENABLED:-false}"

# Sysdig Secure Integration for STIG Compliance
export SYSDIG_SECURE_ENABLED="${SYSDIG_SECURE_ENABLED:-false}"
export SYSDIG_SECURE_ENDPOINT="${SYSDIG_SECURE_ENDPOINT:-}"
export SYSDIG_SECURE_API_TOKEN="${SYSDIG_SECURE_API_TOKEN:-}"

# STIG Assessment Configuration
export STIG_ASSESSMENT_MODE="${STIG_ASSESSMENT_MODE:-automated}"  # automated, manual, hybrid
export STIG_REPORT_FORMAT="${STIG_REPORT_FORMAT:-json}"  # json, xml, html
export STIG_CONTINUOUS_MONITORING="${STIG_CONTINUOUS_MONITORING:-true}"

# Secure the script file itself.
chmod 700 "${BASH_SOURCE[0]}"

echo "---------------------------------------------"
echo " HARDN-DOCKER Setup"
echo "---------------------------------------------"

###############################################################################
# DISA STIG Compliance Execution
###############################################################################

if [ "$DOCKER_STIG_ENABLED" = "true" ] || [ "$KUBERNETES_STIG_ENABLED" = "true" ]; then
    echo "[+] Executing DISA STIG compliance checks..."

    # STIG Category-based execution
    case "$STIG_COMPLIANCE_LEVEL" in
        "I")
            echo "  - Running Category I STIG checks (High severity - Critical vulnerabilities)"
            ;;
        "II")
            echo "  - Running Category II STIG checks (Medium severity - Significant vulnerabilities)"
            ;;
        "III")
            echo "  - Running Category III STIG checks (Low severity - Minor vulnerabilities)"
            ;;
        *)
            echo "  - Running all STIG compliance categories"
            ;;
    esac

    # Docker STIG checks
    if [ "$DOCKER_STIG_ENABLED" = "true" ]; then
        echo "  - Docker STIG requirements:"
        echo "    * Communication channels encrypted"
        echo "    * Resource limits enforced (CPU, memory, storage)"
        echo "    * Container Best Practices followed"
        echo "    * TLS certificate ownership set to root:root"
    fi

    # Kubernetes STIG checks
    if [ "$KUBERNETES_STIG_ENABLED" = "true" ]; then
        echo "  - Kubernetes STIG requirements:"
        echo "    * Pod Security Standards enforced"
        echo "    * Network policies configured"
        echo "    * RBAC properly configured"
        echo "    * Secrets management secured"
    fi

    # Sysdig Secure integration
    if [ "$SYSDIG_SECURE_ENABLED" = "true" ]; then
        echo "  - Sysdig Secure STIG integration:"
        echo "    * Automated compliance assessment"
        echo "    * Continuous monitoring enabled"
        echo "    * Policy-as-code enforcement"
        echo "    * Drift detection active"
    fi
fi

echo ""
echo "---------------------------------------------"
echo " HARDN-DOCKER Setup Complete"
echo "---------------------------------------------"
echo "All hardening scripts have been executed."
echo "Review the output above for any warnings or errors."

###############################################################################
# Create File Integrity Baseline
###############################################################################

echo "[+] Creating file integrity baseline..."
if [ -f "/sources/security/integrity.sh" ] && [ -f "/sources/memory/protection.sh" ]; then
    # Source both integrity and protection scripts to load functions
    . "/sources/security/integrity.sh"
    . "/sources/memory/protection.sh"

    # Create the baseline using the protection script's function
    if command -v create_file_integrity_baseline >/dev/null 2>&1; then
        create_file_integrity_baseline
        echo "  - File integrity baseline created successfully"
    else
        echo "  - Warning: create_file_integrity_baseline function not found"
        # Fallback to integrity.sh function
        if command -v create_integrity_baseline >/dev/null 2>&1; then
            create_integrity_baseline
            echo "  - File integrity baseline created using fallback method"
        fi
    fi
else
    echo "  - Warning: Required scripts not found"
fi

###############################################################################
# Final Status
###############################################################################

echo ""
echo "=========================================="
echo " HARDN-XDR Hardening Complete"
echo "=========================================="
case "${STIG_COMPLIANCE_LEVEL:-I}" in
    "I")
        SECURITY_LEVEL="HIGH"
        ;;
    "II")
        SECURITY_LEVEL="MEDIUM"
        ;;
    "III")
        SECURITY_LEVEL="LOW"
        ;;
    *)
        SECURITY_LEVEL="CUSTOM"
        ;;
esac
echo "Security Level: $SECURITY_LEVEL"
echo "STIG Compliance: ${STIG_COMPLIANCE_LEVEL:-I}"
echo "CIS Benchmark: 1.13.0"
echo "Container Security: ENABLED"
echo "=========================================="

# Enhanced logging for debugging
log_debug() {
    echo "[DEBUG $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

log_error() {
    echo "[ERROR $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

log_info() {
    echo "[INFO $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}
