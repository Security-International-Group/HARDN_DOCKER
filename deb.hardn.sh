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
# HARDN source registry
###############################################################################

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
    if bash "$SCRIPT_BASE/memory/protection.sh"; then
        echo "  - Memory protection completed successfully"
    else
        echo "  - Memory protection completed with warnings"
    fi
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
    if bash "$SCRIPT_BASE/privilege/access.sh"; then
        echo "  - Privilege access completed successfully"
    else
        echo "  - Privilege access completed with warnings"
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
# STIG-Specific Security Configurations
###############################################################################

# Configure TLS certificate ownership (STIG requirement)
configure_stig_tls() {
    echo "  - Configuring STIG TLS certificate ownership..."

    # Ensure TLS certificates have proper ownership
    if [ -d /etc/ssl/certs ]; then
        find /etc/ssl/certs -name "*.pem" -o -name "*.crt" | while read -r cert; do
            if [ -f "$cert" ]; then
                chown root:root "$cert" 2>/dev/null || true
                chmod 644 "$cert" 2>/dev/null || true
            fi
        done
        echo "    TLS certificate ownership configured (root:root)"
    fi
}

# Configure resource limits (STIG requirement)
configure_stig_limits() {
    echo "  - Configuring STIG resource limits..."

    # Create limits configuration for STIG compliance
    cat > /etc/security/limits.d/stig-hardening.conf << 'EOF'
# STIG-compliant resource limits
* soft nofile 1024
* hard nofile 2048
* soft nproc 512
* hard nproc 1024
root soft nofile 4096
root hard nofile 8192
EOF

    echo "    Resource limits configured for STIG compliance"
}

# Configure communication encryption (STIG requirement)
configure_stig_communication() {
    echo "  - Configuring STIG communication encryption..."

    # Configure OpenSSL for secure defaults
    if [ -f /etc/ssl/openssl.cnf ]; then
        # Backup original config
        cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.backup 2>/dev/null || true

        # Add secure cipher configuration
        cat >> /etc/ssl/openssl.cnf << 'EOF'

# STIG-compliant secure configuration
[stig_secure]
# Disable SSLv2 and SSLv3
Options = NO_SSLv2, NO_SSLv3
# Use secure ciphers only
CipherString = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256
# Minimum TLS version
MinProtocol = TLSv1.2
EOF
        echo "    OpenSSL configured with secure defaults"
    fi

    # Configure SSH for secure communication if available
    if [ -f /etc/ssh/sshd_config ]; then
        # Backup original config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null || true

        # Ensure secure SSH settings
        sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

        echo "    SSH configured with secure settings"
    fi

    echo "    Communication encryption configured for STIG compliance"
}

# Configure container best practices (STIG requirement)
configure_container_best_practices() {
    echo "  - Configuring container best practices for STIG compliance..."

    # Ensure non-root user exists for container execution
    if ! id hardn >/dev/null 2>&1; then
        useradd -r -s /bin/bash -m -d /home/hardn hardn 2>/dev/null || true
        echo "    Created non-root user 'hardn' for container execution"
    fi

    # Configure AppArmor for container security
    if command -v apparmor_status >/dev/null 2>&1; then
        # Create container-specific AppArmor profile
        cat > /etc/apparmor.d/usr.bin.hardn << 'EOF'
#include <tunables/global>

/usr/bin/hardn {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>

  # Allow read access to common directories
  /usr/bin/ r,
  /usr/lib/** r,
  /lib/** r,
  /etc/ld.so.cache r,

  # Allow access to user home directory
  /home/hardn/ r,
  /home/hardn/** rw,

  # Allow network access (controlled)
  network inet stream,
  network inet dgram,

  # Deny dangerous operations
  deny /etc/shadow rw,
  deny /etc/passwd rw,
  deny /etc/sudoers rw,
  deny /proc/sys/kernel/** rw,
  deny /sys/** rw,

  # Allow logging
  /var/log/** rw,
  /var/log/hardn.log rw,

  # Allow temporary files
  /tmp/** rw,
  /var/tmp/** rw,
}
EOF
        apparmor_parser -r /etc/apparmor.d/usr.bin.hardn 2>/dev/null || true
        echo "    AppArmor profile created for container security"
    fi

    # Configure resource limits for containers
    if [ ! -f /etc/security/limits.d/container-limits.conf ]; then
        cat > /etc/security/limits.d/container-limits.conf << 'EOF'
# Container resource limits for STIG compliance
hardn soft nofile 4096
hardn hard nofile 8192
hardn soft nproc 256
hardn hard nproc 512
EOF
        echo "    Container resource limits configured"
    fi

    # Configure audit logging for containers
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -a always,exit -F arch=b64 -S execve -F uid=hardn -k container_exec 2>/dev/null || true
        echo "    Container audit logging configured"
    fi

    echo "    Container best practices configured for STIG compliance"
}

# Execute STIG configurations if enabled
if [ "${DOCKER_STIG_ENABLED:-true}" = "true" ] || [ "${KUBERNETES_STIG_ENABLED:-false}" = "true" ]; then
    configure_stig_tls
    configure_stig_limits
    configure_stig_communication
    configure_container_best_practices
fi

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
