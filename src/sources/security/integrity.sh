#!/bin/bash
# HARDN-XDR Security Registry - File Integrity & Compliance
# Native implementations for CIS, DISA STIG, and Lynis compliance

# File Integrity Monitoring (Tripwire/AIDE equivalent)
create_integrity_baseline() {
    echo "Creating file integrity baseline..."

    # Critical system paths to monitor
    CRITICAL_PATHS="/etc /bin /sbin /usr/bin /usr/sbin /lib /lib64"

    # Create baseline using native tools
    for path in $CRITICAL_PATHS; do
        if [ -d "$path" ]; then
            echo "Baselining $path..."
            find "$path" -type f -exec stat -c "%n|%s|%Y|%a|%u|%g|%i" {} \; >> /var/lib/hardn/integrity.baseline 2>/dev/null
        fi
    done

    echo "Integrity baseline created at /var/lib/hardn/integrity.baseline"
}

verify_integrity() {
    echo "Verifying file integrity..."

    if [ ! -f /var/lib/hardn/integrity.baseline ]; then
        echo "No integrity baseline found"
        return 1
    fi

    local violations=0

    while IFS='|' read -r filepath size mtime perms uid gid inode; do
        if [ -e "$filepath" ]; then
            current=$(stat -c "%s|%Y|%a|%u|%g|%i" "$filepath" 2>/dev/null)
            if [ "$current" != "$size|$mtime|$perms|$uid|$gid|$inode" ]; then
                echo "INTEGRITY VIOLATION: $filepath"
                violations=$((violations + 1))
            fi
        else
            echo "FILE MISSING: $filepath"
            violations=$((violations + 1))
        fi
    done < /var/lib/hardn/integrity.baseline

    if [ $violations -eq 0 ]; then
        echo "All files integrity verified"
        return 0
    else
        echo "Found $violations integrity violations"
        return 1
    fi
}

# CIS Compliance Checks
run_cis_checks() {
    echo "Running CIS Docker Benchmark checks..."

    local passed=0
    local failed=0

    # CIS 4.1: Non-root user
    if id hardn >/dev/null 2>&1; then
        echo "✓ CIS 4.1: Non-root user exists"
        passed=$((passed + 1))
    else
        echo "✗ CIS 4.1: Non-root user missing"
        failed=$((failed + 1))
    fi

    # CIS 5.1: AppArmor
    if command -v apparmor_status >/dev/null 2>&1; then
        echo "✓ CIS 5.1: AppArmor available"
        passed=$((passed + 1))
    else
        echo "✗ CIS 5.1: AppArmor not available"
        failed=$((failed + 1))
    fi

    # CIS 5.4: Non-privileged execution
    if [ "$(id -u)" != "0" ]; then
        echo "✓ CIS 5.4: Non-privileged execution"
        passed=$((passed + 1))
    else
        echo "✗ CIS 5.4: Running as root"
        failed=$((failed + 1))
    fi

    echo "CIS Results: $passed passed, $failed failed"
    return $failed
}

# DISA STIG Compliance Checks
run_stig_checks() {
    echo "Running DISA STIG checks..."

    local passed=0
    local failed=0

    # STIG: No empty passwords
    empty_passwords=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [ "$empty_passwords" -eq 0 ]; then
        echo "✓ STIG: No empty passwords"
        passed=$((passed + 1))
    else
        echo "✗ STIG: $empty_passwords empty passwords found"
        failed=$((failed + 1))
    fi

    # STIG: Root only UID 0
    uid_zero=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)
    if [ "$uid_zero" -eq 1 ]; then
        echo "✓ STIG: Only root has UID 0"
        passed=$((passed + 1))
    else
        echo "✗ STIG: $uid_zero accounts with UID 0"
        failed=$((failed + 1))
    fi

    echo "STIG Results: $passed passed, $failed failed"
    return $failed
}

# Security Policy Enforcement
enforce_security_policy() {
    echo "Enforcing security policies..."

    # Remove world-writable files
    world_writable=$(find / -type f -perm -002 2>/dev/null | wc -l)
    if [ "$world_writable" -gt 0 ]; then
        echo "Found $world_writable world-writable files - removing write permissions"
        find / -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null || true
    fi

    # Secure critical directories
    CRITICAL_DIRS="/etc/security /var/log /var/lib/hardn"
    for dir in $CRITICAL_DIRS; do
        if [ -d "$dir" ]; then
            chmod 750 "$dir" 2>/dev/null || true
        fi
    done

    echo "Security policies enforced"
}

# Functions are available when sourced
# export -f create_integrity_baseline
# export -f verify_integrity
# export -f run_cis_checks
# export -f run_stig_checks
# export -f enforce_security_policy

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Security Integrity Setup"
    echo "=================================="

    create_integrity_baseline
    verify_integrity
    run_cis_checks
    run_stig_checks
    enforce_security_policy

    echo ""
    echo "Security integrity configuration completed."
fi
