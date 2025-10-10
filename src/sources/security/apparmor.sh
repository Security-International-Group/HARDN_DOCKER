#!/bin/bash
# HARDN-XDR AppArmor Configuration
# Configure AppArmor for security compliance

# Function to configure AppArmor
configure_apparmor() {
    echo "Configuring AppArmor for compliance..."

    # Check if AppArmor is available
    if ! command -v apparmor_status >/dev/null 2>&1; then
        echo "Warning: AppArmor not installed, skipping configuration"
        return 1
    fi

    # Enable AppArmor service if available
    if systemctl is-active --quiet apparmor 2>/dev/null; then
        systemctl enable apparmor 2>/dev/null || true
    fi

    # Load the HARDN AppArmor profile if it exists
    if [[ -f /etc/apparmor.d/usr.bin.hardn ]]; then
        echo "Loading HARDN AppArmor profile..."
        apparmor_parser -r /etc/apparmor.d/usr.bin.hardn 2>/dev/null || true
    fi

    # Reload AppArmor profiles
    apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true

    # Alternative reload method
    service apparmor reload 2>/dev/null || apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true

    # Configure audit rules for AppArmor if auditd is available
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -a always,exit -F arch=b64 -S all -k apparmor 2>/dev/null || true
    fi

    # Verify AppArmor is enforcing
    if apparmor_status 2>/dev/null | grep -q "usr.bin.hardn.*enforce"; then
        echo "✓ AppArmor profile 'usr.bin.hardn' is loaded and enforcing"
    else
        echo "⚠ AppArmor profile 'usr.bin.hardn' not found or not enforcing"
    fi

    echo "AppArmor configured for compliance."
}

# Function to create AppArmor profile for HARDN
create_hardn_apparmor_profile() {
    echo "Creating HARDN AppArmor profile..."

    # Create the profile directory if it doesn't exist
    mkdir -p /etc/apparmor.d

    # Create the AppArmor profile for HARDN
    cat > /etc/apparmor.d/usr.bin.hardn << 'EOF'
#include <tunables/global>

profile hardn /usr/local/bin/entrypoint.sh {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Allow read access to necessary files
  /usr/local/bin/entrypoint.sh r,
  /usr/local/bin/deb.hardn.sh r,
  /usr/local/bin/health_check.sh r,
  /usr/local/bin/smoke_test.sh r,
  /sources/** r,
  /etc/passwd r,
  /etc/group r,
  /etc/ssl/certs/** r,
  /etc/localtime r,
  /proc/*/status r,
  /proc/version r,
  /sys/kernel/mm/transparent_hugepage/enabled r,

  # Allow execution of scripts
  /usr/local/bin/deb.hardn.sh x,
  /usr/local/bin/health_check.sh x,
  /usr/local/bin/smoke_test.sh x,
  /sources/**/*.sh x,

  # Allow network access
  network inet stream,
  network inet dgram,

  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability dac_override,
  deny capability dac_read_search,
  deny capability setgid,
  deny capability setuid,
  deny capability chown,

  # Allow basic capabilities needed for operation (excluding chown)
  capability fsetid,
  capability kill,
  capability setpcap,

  # Allow writing to allowed directories
  /var/log/** w,
  /var/lib/hardn/** w,
  /tmp/** w,
  /opt/hardn-xdr/** w,

  # Allow reading from /proc and /sys for monitoring
  /proc/** r,
  /sys/** r,

  # Allow signal handling
  signal (send,receive) peer=hardn,
}
EOF

    echo "HARDN AppArmor profile created."
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    configure_apparmor
    create_hardn_apparmor_profile
fi
