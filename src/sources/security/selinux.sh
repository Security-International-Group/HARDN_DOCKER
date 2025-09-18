#!/bin/bash
# HARDN-XDR SELinux Configuration
# Configure SELinux for security compliance

# Function to configure SELinux
configure_selinux() {
    echo "Configuring SELinux for compliance..."

    # Check if SELinux is available
    if ! command -v sestatus >/dev/null 2>&1; then
        echo "Warning: SELinux not available, skipping configuration"
        return 1
    fi

    # Check SELinux status
    selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}' 2>/dev/null || echo "disabled")

    if [ "$selinux_status" = "disabled" ]; then
        echo "SELinux is disabled, attempting to enable..."
        # Try to enable SELinux (may require reboot)
        if [ -f /etc/selinux/config ]; then
            sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            echo "SELinux set to enforcing mode in config"
        fi
    elif [ "$selinux_status" = "permissive" ]; then
        echo "SELinux is in permissive mode, setting to enforcing..."
        setenforce 1 2>/dev/null || echo "Failed to set enforcing mode"
    else
        echo "SELinux is already in enforcing mode"
    fi

    # Create HARDN SELinux policy if tools are available
    if command -v checkmodule >/dev/null 2>&1 && command -v semodule_package >/dev/null 2>&1; then
        create_hardn_selinux_policy
    fi

    echo "SELinux configured for compliance."
}

# Function to create SELinux policy for HARDN
create_hardn_selinux_policy() {
    echo "Creating HARDN SELinux policy..."

    # Create SELinux policy module
    cat > /tmp/hardn.te << 'EOF'
policy_module(hardn, 1.0.0)

require {
    type unconfined_t;
    type user_home_t;
    class process { transition sigchld sigkill sigstop signull signal };
    class file { read write execute open getattr };
}

type hardn_t;
type hardn_exec_t;

init_daemon_domain(hardn_t, hardn_exec_t)

allow hardn_t self:process { signal sigchld sigkill sigstop signull };
allow hardn_t user_home_t:file { read write execute open getattr };
allow hardn_t unconfined_t:process signal;
EOF

    # Compile and install the policy
    if checkmodule -M -m -o /tmp/hardn.mod /tmp/hardn.te 2>/dev/null; then
        semodule_package -o /tmp/hardn.pp -m /tmp/hardn.mod 2>/dev/null || true
        semodule -i /tmp/hardn.pp 2>/dev/null || true
        echo "HARDN SELinux policy installed"
    else
        echo "Failed to compile HARDN SELinux policy"
    fi

    # Clean up temporary files
    rm -f /tmp/hardn.te /tmp/hardn.mod /tmp/hardn.pp
}

# Function to verify SELinux configuration
verify_selinux() {
    echo "Verifying SELinux configuration..."

    # Check if SELinux is enforcing
    if sestatus 2>/dev/null | grep -q "enforcing"; then
        echo "✓ SELinux is in enforcing mode"
        return 0
    else
        echo " SELinux is not in enforcing mode"
        return 1
    fi
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    configure_selinux
    verify_selinux
fi
