#!/bin/bash
# HARDN-XDR Tripwire Registry - File Integrity Monitoring
# Mirrors tripwire functionality using native Linux tools

# Tripwire-like file integrity monitoring using find, stat, and sha256sum
create_file_integrity_db() {
    echo "Creating Tripwire-style file integrity database..."

    # Critical system directories to monitor
    CRITICAL_PATHS="/etc /bin /sbin /usr/bin /usr/sbin /lib /lib64"

    # Create integrity database
    for path in $CRITICAL_PATHS; do
        if [ -d "$path" ]; then
            echo "Scanning $path..."
            find "$path" -type f -exec sha256sum {} \; 2>/dev/null >> /var/lib/hardn/tripwire.db
        fi
    done

    echo "File integrity database created at /var/lib/hardn/tripwire.db"
}

verify_file_integrity() {
    echo "Verifying file integrity (Tripwire-style)..."

    if [ ! -f /var/lib/hardn/tripwire.db ]; then
        echo "No integrity database found. Run create_file_integrity_db first."
        return 1
    fi

    local violations=0

    while IFS=' ' read -r hash filepath; do
        if [ -f "$filepath" ]; then
            current_hash=$(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1)
            if [ "$hash" != "$current_hash" ]; then
                echo "INTEGRITY VIOLATION: $filepath"
                violations=$((violations + 1))
            fi
        else
            echo "FILE MISSING: $filepath"
            violations=$((violations + 1))
        fi
    done < /var/lib/hardn/tripwire.db

    if [ $violations -eq 0 ]; then
        echo "All files integrity verified successfully"
        return 0
    else
        echo "Found $violations integrity violations"
        return 1
    fi
}

# Tripwire policy rules (CIS/DISA STIG compliant)
setup_tripwire_policy() {
    echo "Setting up Tripwire-style monitoring policy..."

    # CIS 6.2.4.1: Ensure permissions on bootloader config are configured
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

    # CIS 6.2.4.2: Ensure bootloader password is set
    if [ -f /boot/grub/grub.cfg ]; then
        if ! grep -q "password" /boot/grub/grub.cfg; then
            echo "WARNING: Bootloader password not set"
        fi
    fi

    # Monitor critical configuration files
    CRITICAL_FILES="/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config"
    for file in $CRITICAL_FILES; do
        if [ -f "$file" ]; then
            echo "Monitoring $file for changes"
            # Add to monitoring list
            echo "$file" >> /var/lib/hardn/critical-files.list
        fi
    done
}

# Functions are available when sourced
# export -f create_file_integrity_db
# export -f verify_file_integrity
# export -f setup_tripwire_policy

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Tripwire Registry Setup"
    echo "================================="

    create_file_integrity_db
    verify_file_integrity
    setup_tripwire_policy

    echo ""
    echo "Tripwire registry configuration completed."
fi
