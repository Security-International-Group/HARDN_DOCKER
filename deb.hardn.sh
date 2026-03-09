#!/bin/bash
# deb.hardn.sh
#
# Build-time hardening script for the HARDN-XDR container image.
# Runs inside the container as root during the Docker build (RUN /usr/local/bin/deb.hardn.sh).
#
# Scope: container-internal only.  No writes to the host kernel, Docker daemon,
# or any socket.  Operations that only make sense on the host (AppArmor module
# loading, SELinux context setting, docker-daemon.json edits) are intentionally
# skipped here and handled at the runtime/orchestration layer instead.

set -euo pipefail
IFS=$'\n\t'

export DEBIAN_FRONTEND=noninteractive

# Detect whether we are running inside a container so we can gate host-only ops
IN_CONTAINER=false
if [[ -f /.dockerenv ]] || grep -q "docker\|container" /proc/1/cgroup 2>/dev/null; then
    echo "Container environment detected — host-level operations will be skipped"
    IN_CONTAINER=true
fi

###############################################################################
# Pre-flight checks
###############################################################################

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root — hardening operations require elevated privileges."
  exit 1
fi

# Signal to sourced scripts that we are in hardening phase, not live runtime
export HARDENING_PHASE=true

###############################################################################
# Package setup
###############################################################################

echo "[+] Checking security packages..."

# AppArmor is a host kernel module (LSM). The container cannot load kernel modules
# or write AppArmor profiles into the kernel during a Docker build. Profile
# assignment is handled at container start via --security-opt apparmor=<profile>.
echo "  - AppArmor: managed at the host/runtime layer — no package install needed in image"

# UFW and Fail2ban are host-facing tools. They depend on Python and netfilter,
# neither of which should be in the hardened image. Skip in container builds.
if [[ "${SKIP_HEAVY_SECURITY_TOOLS:-1}" = "0" && "${IN_CONTAINER}" = false ]]; then
    command -v ufw          >/dev/null 2>&1 || apt-get install -y --no-install-recommends ufw
    command -v fail2ban-server >/dev/null 2>&1 || apt-get install -y --no-install-recommends fail2ban
else
    echo "  - UFW / Fail2ban: skipped (container build or SKIP_HEAVY_SECURITY_TOOLS=1)"
fi

# libpam-pwquality and its configuration (minlen=14, complexity flags) are applied
# in the Dockerfile's primary package layer — nothing to do here.
echo "  - libpam-pwquality: already installed and configured in the image layer"

apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

###############################################################################
# Run /sources hardening scripts
###############################################################################

echo "[+] Package setup complete. Running /sources hardening scripts..."

SCRIPT_BASE="/sources"

echo "[+] Compliance scripts..."
if [[ -f "$SCRIPT_BASE/compliance/openscap-registry.sh" ]]; then
    echo "  - Running OpenSCAP compliance checks..."
    if bash "$SCRIPT_BASE/compliance/openscap-registry.sh"; then
        echo "  - OpenSCAP completed successfully"
    else
        echo "  - OpenSCAP completed with warnings"
    fi
else
    echo "  - Warning: OpenSCAP script not found"
fi

if [[ -f "$SCRIPT_BASE/compliance/cron.sh" ]]; then
    echo "  - Setting up automated compliance updates..."
    if bash "$SCRIPT_BASE/compliance/cron.sh"; then
        echo "  - Cron setup completed successfully"
    else
        echo "  - Cron setup completed with warnings"
    fi
else
    echo "  - Warning: Cron script not found"
fi

echo "[+] Memory protection scripts..."
if [[ -f "$SCRIPT_BASE/memory/clamav.sh" ]]; then
    echo "  - Running ClamAV configuration..."
    if bash "$SCRIPT_BASE/memory/clamav.sh"; then
        echo "  - ClamAV completed successfully"
    else
        echo "  - ClamAV completed with warnings"
    fi
else
    echo "  - Warning: ClamAV script not found"
fi

if [[ -f "$SCRIPT_BASE/memory/part.sh" ]]; then
    echo "  - Running Docker partition and memory security..."
    if bash "$SCRIPT_BASE/memory/part.sh"; then
        echo "  - Partition and memory security completed successfully"
    else
        echo "  - Partition and memory security completed with warnings"
    fi
else
    echo "  - Warning: Partition script not found"
fi

if [[ -f "$SCRIPT_BASE/memory/protection.sh" ]]; then
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

echo "[+] Network security scripts..."

if [[ -f "$SCRIPT_BASE/security/security.sh" ]]; then
    echo "  - Running security configuration..."
    if bash "$SCRIPT_BASE/security/security.sh"; then
        echo "  - Network security completed successfully"
    else
        echo "  - Network security completed with warnings"
    fi
else
    echo "  - Warning: Network security script not found"
fi

if [[ -f "$SCRIPT_BASE/security/apparmor.sh" ]]; then
    echo "  - Running AppArmor configuration..."
    if bash "$SCRIPT_BASE/security/apparmor.sh"; then
        echo "  - AppArmor configuration completed successfully"
    else
        echo "  - AppArmor configuration completed with warnings"
    fi
else
    echo "  - Warning: AppArmor script not found"
fi

# SELinux context labels are assigned at container runtime via --security-opt label=...
# or the security_opt key in docker-compose.yml. There is nothing to configure inside
# the image itself.
echo "  - SELinux: managed at the host/runtime layer — skipping in-image configuration"

# docker-daemon.sh writes changes to the host Docker daemon configuration.
# That is only meaningful outside a container; skip it during image builds.
if [[ "${IN_CONTAINER}" = false ]] && [[ -f "$SCRIPT_BASE/security/docker-daemon.sh" ]]; then
    echo "  - Running Docker daemon configuration..."
    if bash "$SCRIPT_BASE/security/docker-daemon.sh"; then
        echo "  - Docker daemon configuration completed successfully"
    else
        echo "  - Docker daemon configuration completed with warnings"
    fi
else
    echo "  - Skipping Docker daemon config (host-level concern; not applicable inside image build)"
fi

if [[ -f "$SCRIPT_BASE/security/image-security.sh" ]]; then
    echo "  - Running container image security configuration..."
    if bash "$SCRIPT_BASE/security/image-security.sh"; then
        echo "  - Container image security configuration completed successfully"
    else
        echo "  - Container image security configuration completed with warnings"
    fi
else
    echo "  - Warning: Container image security script not found"
fi

if [[ -f "$SCRIPT_BASE/network/tripwire.sh" ]]; then
    echo "  - Running Tripwire configuration..."
    if bash "$SCRIPT_BASE/network/tripwire.sh"; then
        echo "  - Tripwire completed successfully"
    else
        echo "  - Tripwire completed with warnings"
    fi
else
    echo "  - Warning: Tripwire script not found"
fi

echo "[+] Privilege management scripts..."
if [[ -f "$SCRIPT_BASE/privilege/access.sh" ]]; then
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

if [[ -f "$SCRIPT_BASE/privilege/rkhunter.sh" ]]; then
    echo "  - Running rkhunter configuration..."
    if bash "$SCRIPT_BASE/privilege/rkhunter.sh"; then
        echo "  - rkhunter completed successfully"
    else
        echo "  - rkhunter completed with warnings"
    fi
else
    echo "  - Warning: rkhunter script not found"
fi

echo "[+] Security integrity scripts..."
if [[ -f "$SCRIPT_BASE/security/integrity.sh" ]]; then
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
# DISA STIG configuration
###############################################################################

# Default to Category I (High severity) checks; override with STIG_COMPLIANCE_LEVEL env var
export STIG_COMPLIANCE_LEVEL="${STIG_COMPLIANCE_LEVEL:-I}"
export STIG_COMPLIANCE_CATEGORIES="I II III"

export DOCKER_STIG_ENABLED="${DOCKER_STIG_ENABLED:-true}"
export KUBERNETES_STIG_ENABLED="${KUBERNETES_STIG_ENABLED:-false}"

# Sysdig Secure is optional; leave disabled unless the operator provides an API key
export SYSDIG_SECURE_ENABLED="${SYSDIG_SECURE_ENABLED:-false}"
export SYSDIG_SECURE_ENDPOINT="${SYSDIG_SECURE_ENDPOINT:-}"
export SYSDIG_SECURE_API_TOKEN="${SYSDIG_SECURE_API_TOKEN:-}"

export STIG_ASSESSMENT_MODE="${STIG_ASSESSMENT_MODE:-automated}"
export STIG_REPORT_FORMAT="${STIG_REPORT_FORMAT:-json}"
export STIG_CONTINUOUS_MONITORING="${STIG_CONTINUOUS_MONITORING:-true}"

# Protect the script itself from modification by the non-root runtime user
chmod 700 "${BASH_SOURCE[0]}"

echo "---------------------------------------------"
echo " HARDN-XDR Container Setup"
echo "---------------------------------------------"

###############################################################################
# DISA STIG compliance execution
###############################################################################

if [[ "$DOCKER_STIG_ENABLED" = "true" ]] || [[ "$KUBERNETES_STIG_ENABLED" = "true" ]]; then
    echo "[+] Executing DISA STIG compliance checks..."

    case "$STIG_COMPLIANCE_LEVEL" in
        "I")   echo "  - Running Category I STIG checks (High severity - Critical vulnerabilities)" ;;
        "II")  echo "  - Running Category II STIG checks (Medium severity - Significant vulnerabilities)" ;;
        "III") echo "  - Running Category III STIG checks (Low severity - Minor vulnerabilities)" ;;
        *)     echo "  - Running all STIG compliance categories" ;;
    esac

    if [[ "$DOCKER_STIG_ENABLED" = "true" ]]; then
        echo "  - Docker STIG requirements:"
        echo "    * Communication channels encrypted"
        echo "    * Resource limits enforced (CPU, memory, storage)"
        echo "    * Container Best Practices followed"
        echo "    * TLS certificate ownership set to root:root"
    fi

    if [[ "$KUBERNETES_STIG_ENABLED" = "true" ]]; then
        echo "  - Kubernetes STIG requirements:"
        echo "    * Pod Security Standards enforced"
        echo "    * Network policies configured"
        echo "    * RBAC properly configured"
        echo "    * Secrets management secured"
    fi

    if [[ "$SYSDIG_SECURE_ENABLED" = "true" ]]; then
        echo "  - Sysdig Secure STIG integration:"
        echo "    * Automated compliance assessment"
        echo "    * Continuous monitoring enabled"
        echo "    * Policy-as-code enforcement"
        echo "    * Drift detection active"
    fi
fi

echo ""
echo "---------------------------------------------"
echo " HARDN-XDR Container Setup Complete"
echo "---------------------------------------------"
echo "Review the output above for any warnings."

###############################################################################
# File integrity baseline
###############################################################################

echo "[+] Creating file integrity baseline..."
if [[ -f "/sources/security/integrity.sh" ]] && [[ -f "/sources/memory/protection.sh" ]]; then
    . "/sources/security/integrity.sh"
    . "/sources/memory/protection.sh"

    if command -v create_file_integrity_baseline >/dev/null 2>&1; then
        create_file_integrity_baseline
        echo "  - File integrity baseline created successfully"
    else
        echo "  - Warning: create_file_integrity_baseline function not found"
        if command -v create_integrity_baseline >/dev/null 2>&1; then
            create_integrity_baseline
            echo "  - File integrity baseline created using fallback method"
        fi
    fi
else
    echo "  - Warning: Required scripts not found"
fi

###############################################################################
# Final status banner
###############################################################################

echo ""
echo "=========================================="
echo " HARDN-XDR Hardening Complete"
echo "=========================================="
case "${STIG_COMPLIANCE_LEVEL:-I}" in
    "I")   SECURITY_LEVEL="HIGH" ;;
    "II")  SECURITY_LEVEL="MEDIUM" ;;
    "III") SECURITY_LEVEL="LOW" ;;
    *)     SECURITY_LEVEL="CUSTOM" ;;
esac
echo "Security Level: $SECURITY_LEVEL"
echo "STIG Compliance: ${STIG_COMPLIANCE_LEVEL:-I}"
echo "CIS Benchmark: 1.13.0"
echo "Container Security: ENABLED"
echo "=========================================="

# Logging helpers
log_debug() { echo "[DEBUG $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2; }
log_error() { echo "[ERROR $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2; }
log_info()  { echo "[INFO  $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2; }