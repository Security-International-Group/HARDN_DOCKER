#!/bin/bash
# HARDN-XDR Privilege Registry - Access Control & Privilege Management
# Native implementations for privilege escalation prevention

# SUID/SGID File Management
audit_suid_sgid_files() {
    echo "Auditing SUID/SGID files..."

    # Find all SUID/SGID files
    suid_files=$(find / -type f -perm /6000 2>/dev/null)

    if [ -n "$suid_files" ]; then
        echo "Found SUID/SGID files:"
        echo "$suid_files" | while read -r file; do
            perms=$(stat -c "%a" "$file" 2>/dev/null)
            owner=$(stat -c "%U" "$file" 2>/dev/null)
            echo "  $file (perms: $perms, owner: $owner)"
        done
    else
        echo "No SUID/SGID files found"
    fi
}

# Remove Dangerous SUID/SGID Files
remove_dangerous_suid() {
    echo "Removing dangerous SUID/SGID files..."

    DANGEROUS_SUID="/usr/bin/su /bin/su /usr/bin/sudo /bin/sudo"

    for file in $DANGEROUS_SUID; do
        if [ -f "$file" ] && [ -u "$file" ]; then
            echo "Removing SUID bit from $file"
            chmod u-s "$file" 2>/dev/null || true
        fi
    done

    echo "Dangerous SUID files secured"
}

# PAM Configuration for Access Control
configure_pam_security() {
    echo "Configuring PAM security..."

    # Ensure PAM packages are available
    if ! command -v pam-auth-update >/dev/null 2>&1; then
        echo "Warning: PAM tools not available"
        return 1
    fi

    # Install pam_pwquality if not available
    if ! dpkg -l | grep -q libpam-pwquality; then
        echo "Installing libpam-pwquality..."
        apt-get update && apt-get install -y libpam-pwquality || {
            echo "Failed to install libpam-pwquality"
            return 1
        }
    fi

    # Configure password quality - ensure pam_pwquality is available
    if [ -f /etc/pam.d/common-password ]; then
        # Check if pam_pwquality is already configured with minlen=8
        if ! grep -q "pam_pwquality.so.*minlen=8" /etc/pam.d/common-password; then
            # Add pam_pwquality configuration before pam_unix
            sed -i '/password.*\[success=1 default=ignore\].*pam_unix.so/i password requisite pam_pwquality.so minlen=8' /etc/pam.d/common-password 2>/dev/null || {
                echo "Failed to update common-password"
                return 1
            }
        fi
    else
        echo "Warning: /etc/pam.d/common-password not found"
        return 1
    fi

    # Configure account locking
    if [ -f /etc/pam.d/common-auth ]; then
        if ! grep -q "pam_tally2.so" /etc/pam.d/common-auth; then
            echo "auth required pam_tally2.so deny=5 unlock_time=900" >> /etc/pam.d/common-auth 2>/dev/null || true
        fi
    fi

    # Configure session limits
    if [ -f /etc/pam.d/common-session ]; then
        if ! grep -q "pam_limits.so" /etc/pam.d/common-session; then
            echo "session required pam_limits.so" >> /etc/pam.d/common-session 2>/dev/null || true
        fi
    fi

    echo "PAM security configured successfully"
}

# User Access Control
configure_user_access() {
    echo "Configuring user access controls..."

    # Lock inactive accounts
    useradd -D -f 30 2>/dev/null || true

    # Set password aging
    if [ -f /etc/login.defs ]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs 2>/dev/null || true
    fi

    echo "User access controls configured"
}

# Privilege Escalation Prevention
prevent_privilege_escalation() {
    echo "Configuring privilege escalation prevention..."

    # Disable unprivileged user namespaces
    echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf

    # Restrict dmesg access
    echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf

    # Disable kexec (if not needed)
    echo "kernel.kexec_load_disabled = 1" >> /etc/sysctl.conf

    # Apply settings
    if [[ -f /.dockerenv ]] || grep -q "docker\|container" /proc/1/cgroup 2>/dev/null; then
        echo "Container environment detected - skipping sysctl application"
    else
        sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || echo "Warning: Some sysctl settings could not be applied"
    fi

    echo "Privilege escalation prevention configured"
}

# Root Access Control
configure_root_access() {
    echo "Configuring root access controls..."

    # Secure root home directory
    if [ -d /root ]; then
        chmod 700 /root 2>/dev/null || true
        # Skip chown on read-only filesystem
        if ! mount | grep -q " / ro," 2>/dev/null; then
            chown root:root /root 2>/dev/null || true
        fi
    fi

    # Configure secure root shell
    if [ -f /etc/passwd ]; then
        sed -i 's|^root:.*$|root:x:0:0:root:/root:/bin/bash|' /etc/passwd 2>/dev/null || true
    fi

    echo "Root access controls configured"
}

# Wheel Group Configuration
configure_wheel_group() {
    echo "Configuring wheel group for sudo access..."

    # Create wheel group if it doesn't exist
    if ! getent group wheel >/dev/null 2>&1; then
        groupadd wheel 2>/dev/null || true
    fi

    # Configure sudo to require wheel group
    if [ -f /etc/sudoers ]; then
        echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers 2>/dev/null || true
    fi

    echo "Wheel group configured"
}

# Session Security
configure_session_security() {
    echo "Configuring session security..."

    # Set session timeout
    if [ -f /etc/profile ]; then
        echo "TMOUT=900" >> /etc/profile
        echo "readonly TMOUT" >> /etc/profile
        echo "export TMOUT" >> /etc/profile
    fi

    # Configure secure umask
    echo "umask 027" >> /etc/profile

    echo "Session security configured"
}

# Audit User Activities
audit_user_activities() {
    echo "Setting up user activity auditing..."

    # Configure audit rules for user activities
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -w /etc/passwd -p wa -k passwd_changes 2>/dev/null || true
        auditctl -w /etc/shadow -p wa -k shadow_changes 2>/dev/null || true
        auditctl -w /etc/sudoers -p wa -k sudoers_changes 2>/dev/null || true
        auditctl -w /var/log/auth.log -p wa -k auth_logs 2>/dev/null || true
    fi

    echo "User activity auditing configured"
}

# Functions are available when sourced
# export -f audit_suid_sgid_files
# export -f remove_dangerous_suid
# export -f configure_pam_security
# export -f configure_user_access
# export -f prevent_privilege_escalation
# export -f configure_root_access
# export -f configure_wheel_group
# export -f configure_session_security
# export -f audit_user_activities

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Privilege Access Setup"
    echo "================================"

    audit_suid_sgid_files
    remove_dangerous_suid
    configure_pam_security
    configure_user_access
    prevent_privilege_escalation
    configure_root_access
    configure_wheel_group
    configure_session_security
    audit_user_activities

    echo ""
    echo "Privilege access configuration completed."
fi
