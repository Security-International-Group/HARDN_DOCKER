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

    # Reload AppArmor profiles
    apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true

    # Alternative reload method
    service apparmor reload 2>/dev/null || apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true

    # Configure audit rules for AppArmor if auditd is available
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -a always,exit -F arch=b64 -S all -k apparmor 2>/dev/null || true
    fi

    echo "AppArmor configured for compliance."
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    configure_apparmor
fi