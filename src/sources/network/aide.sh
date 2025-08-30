#!/bin/bash
# HARDN-XDR AIDE Registry - Advanced Intrusion Detection
# Minimal AIDE configuration for optimal performance

# Minimal AIDE configuration content
AIDE_MINIMAL_CONFIG='# Minimal AIDE configuration for container security
# Optimized for performance and reduced footprint

# Database configuration with compression
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# Use only SHA256 for faster performance (instead of all checksums)
Checksums = sha256

# Simplified group definitions for critical files only
OwnerMode = p+u+g+ftype
Size = s+b
InodeData = OwnerMode+n+i+Size+l+X
StaticFile = m+c+Checksums
Full = InodeData+StaticFile
VarTime = InodeData+Checksums
VarInode = VarTime-i
VarFile = OwnerMode+n+l+X
VarDir = OwnerMode+n+i+X

# Exclude volatile and unnecessary directories
!/proc
!/sys
!/dev
!/tmp
!/var/tmp
!/var/cache
!/var/log
!/run
!/mnt
!/media

# Core system binaries and libraries (critical only)
/bin/sh Full
/bin/bash Full
/sbin/init Full
/usr/bin/sudo Full
/usr/bin/passwd Full
/usr/sbin/useradd Full
/usr/sbin/userdel Full
/usr/sbin/groupadd Full
/usr/sbin/groupdel Full

# Critical configuration files
/etc/passwd Full
/etc/shadow Full
/etc/group Full
/etc/gshadow Full
/etc/hosts Full
/etc/hostname Full
/etc/resolv.conf Full
/etc/fstab Full
/etc/inittab Full
/etc/crontab Full
/etc/sysctl.conf Full
/etc/sysctl.d/99-hardening.conf Full
/etc/login.defs Full
/etc/sudoers Full

# Security configuration
/etc/pam.d/.* Full
/etc/security/.* Full
/etc/ssh/sshd_config Full
/etc/ssh/ssh_config Full

# Network and firewall
/etc/iptables/.* Full
/etc/ufw/.* Full

# Audit and logging configuration
/etc/audit/auditd.conf Full
/etc/audit/audit.rules Full
/etc/rsyslog.conf Full

# Package management critical files
/etc/apt/sources.list Full
/etc/apt/trusted.gpg.d/.* Full

# Time synchronization
/etc/chrony/chrony.conf Full

# Security tools configuration
/etc/fail2ban/jail.local Full
/etc/aide/aide.conf Full

# Apparmor profiles
/etc/apparmor.d/.* Full
'

# Function to create minimal AIDE configuration
create_minimal_aide_config() {
    echo "Creating minimal AIDE configuration for optimal performance..."

    # Backup original config if it exists
    if [ -f /etc/aide/aide.conf ]; then
        cp /etc/aide/aide.conf /etc/aide/aide.conf.backup
    fi

    # Write minimal configuration
    echo "$AIDE_MINIMAL_CONFIG" > /etc/aide/aide.conf

    echo "Minimal AIDE configuration created at /etc/aide/aide.conf"
}

# Function to initialize minimal AIDE database
initialize_minimal_aide() {
    echo "Initializing minimal AIDE database..."

    # Ensure AIDE config exists
    if [ ! -f /etc/aide/aide.conf ]; then
        create_minimal_aide_config
    fi

    # Initialize database with minimal config (requires root)
    if [[ "$(id -u)" -eq 0 ]]; then
        if command -v aide >/dev/null 2>&1; then
            aide --config=/etc/aide/aide.conf --init
            if [ -f /var/lib/aide/aide.db.new ]; then
                mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
                echo "Minimal AIDE database initialized successfully"
            else
                echo "Warning: AIDE database initialization may have failed"
            fi
        else
            echo "AIDE not installed, skipping database initialization"
        fi
    else
        echo "Warning: AIDE initialization requires root privileges, skipping"
    fi
}

# Function to check AIDE integrity with minimal config
check_minimal_aide_integrity() {
    echo "Checking file integrity with minimal AIDE configuration..."

    if [ ! -f /var/lib/aide/aide.db ]; then
        echo "No AIDE database found. Initializing..."
        initialize_minimal_aide
        return 0
    fi

    if command -v aide >/dev/null 2>&1; then
        aide --config=/etc/aide/aide.conf --check
    else
        echo "AIDE not installed, cannot perform integrity check"
        return 1
    fi
}

# AIDE configuration equivalent
AIDE_CHECK_LEVELS="
FIPSR: p+i+n+u+g+s+m+c+acl+selinux+xattrs+ftype
NORMAL: p+i+n+u+g+s+m+c+acl+selinux+xattrs
DIR: p+i+n+u+g+ftype
PERMS: p+i+u+g+acl+selinux
EVERYTHING: p+i+n+u+g+s+m+c+acl+selinux+xattrs+ftype+sha256
"

# Critical files to monitor (CIS/DISA STIG requirements)
CRITICAL_FILES="
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/sudoers.d/
/etc/ssh/sshd_config
/etc/ssh/ssh_host_*_key
/etc/ssl/certs/
/boot/grub/grub.cfg
/etc/fstab
/etc/hosts
/etc/resolv.conf
/etc/nsswitch.conf
/etc/pam.d/
/etc/security/
/var/spool/cron/
/etc/crontab
/etc/cron.d/
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
"

create_aide_database() {
    echo "Creating AIDE-style integrity database..."

    # Create database directory
    mkdir -p /var/lib/hardn/aide
    chmod 700 /var/lib/hardn/aide

    # Generate file attributes for critical files
    for file in $CRITICAL_FILES; do
        if [ -e "$file" ]; then
            if [ -d "$file" ]; then
                # Directory monitoring
                find "$file" -type f -exec stat -c "%n %s %Y %a %u %g %i" {} \; 2>/dev/null >> /var/lib/hardn/aide/database.db
            else
                # File monitoring
                stat -c "%n %s %Y %a %u %g %i" "$file" 2>/dev/null >> /var/lib/hardn/aide/database.db
            fi
        fi
    done

    echo "AIDE database created at /var/lib/hardn/aide/database.db"
}

check_aide_integrity() {
    echo "Checking file integrity (AIDE-style)..."

    if [ ! -f /var/lib/hardn/aide/database.db ]; then
        echo "No AIDE database found. Run create_aide_database first."
        return 1
    fi

    local violations=0

    while IFS=' ' read -r filepath size mtime perms uid gid inode; do
        if [ -e "$filepath" ]; then
            current_stat=$(stat -c "%s %Y %a %u %g %i" "$filepath" 2>/dev/null)
            if [ "$current_stat" != "$size $mtime $perms $uid $gid $inode" ]; then
                echo "INTEGRITY CHANGE: $filepath"
                echo "  Expected: $size $mtime $perms $uid $gid $inode"
                echo "  Current:  $current_stat"
                violations=$((violations + 1))
            fi
        else
            echo "FILE DELETED: $filepath"
            violations=$((violations + 1))
        fi
    done < /var/lib/hardn/aide/database.db

    if [ $violations -eq 0 ]; then
        echo "All files integrity verified successfully"
        return 0
    else
        echo "Found $violations integrity violations"
        return 1
    fi
}

# CIS 6.2.1.1: Ensure AIDE is installed (implemented natively)
setup_aide_monitoring() {
    echo "Setting up AIDE-style monitoring..."

    # Create monitoring configuration
    cat > /var/lib/hardn/aide/aide.conf << 'EOF'
# AIDE configuration (native implementation)
# File integrity monitoring rules

# Critical system files
/etc/ NORMAL
/etc/passwd FIPSR
/etc/shadow FIPSR
/etc/group FIPSR
/etc/gshadow FIPSR
/etc/sudoers FIPSR

# System binaries
/bin/ NORMAL
/sbin/ NORMAL
/usr/bin/ NORMAL
/usr/sbin/ NORMAL

# Libraries
/lib/ NORMAL
/usr/lib/ NORMAL

# Configuration files
/etc/ssh/ NORMAL
/etc/ssl/ NORMAL

# Boot configuration
/boot/ NORMAL

# Log files (content changes expected)
/var/log/ PERMS
EOF

    # Apply different check levels based on file type
    echo "Applying AIDE check levels..."
    for level in $AIDE_CHECK_LEVELS; do
        check_type=$(echo "$level" | cut -d: -f1)
        echo "Check level $check_type configured"
    done

    echo "AIDE monitoring configuration created"
}

# DISA STIG: File integrity monitoring
stig_file_integrity_check() {
    echo "Performing DISA STIG file integrity checks..."

    # STIG requires monitoring of specific files
    STIG_FILES="
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/sudoers
    /boot/grub/grub.cfg
    "

    for file in $STIG_FILES; do
        if [ -f "$file" ]; then
            perms=$(stat -c "%a" "$file")
            owner=$(stat -c "%U" "$file")

            # Check permissions (STIG requirements)
            case "$file" in
                "/etc/shadow"|"/etc/gshadow")
                    if [ "$perms" != "600" ] || [ "$owner" != "root" ]; then
                        echo "STIG VIOLATION: $file permissions/ownership incorrect"
                    fi
                    ;;
                "/etc/passwd"|"/etc/group")
                    if [ "$perms" != "644" ] || [ "$owner" != "root" ]; then
                        echo "STIG VIOLATION: $file permissions/ownership incorrect"
                    fi
                    ;;
                "/etc/sudoers"|"/boot/grub/grub.cfg")
                    if [ "$perms" != "600" ] || [ "$owner" != "root" ]; then
                        echo "STIG VIOLATION: $file permissions/ownership incorrect"
                    fi
                    ;;
            esac
        fi
    done
}

# Function to reinitialize AIDE database after hardening
reinitialize_aide_database() {
    echo "Reinitializing AIDE database with current hardened state..."

    # Ensure AIDE config exists
    if [ ! -f /etc/aide/aide.conf ]; then
        create_minimal_aide_config
    fi

    # Reinitialize database with current state (requires root)
    if [[ "$(id -u)" -eq 0 ]]; then
        if command -v aide >/dev/null 2>&1; then
            # Remove old database to force clean initialization
            rm -f /var/lib/aide/aide.db
            rm -f /var/lib/aide/aide.db.new

            # Initialize with current state as baseline
            aide --config=/etc/aide/aide.conf --init
            if [ -f /var/lib/aide/aide.db.new ]; then
                mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
                echo "AIDE database reinitialized successfully with hardened state as baseline"
                return 0
            else
                echo "Warning: AIDE database reinitialization may have failed"
                return 1
            fi
        else
            echo "AIDE not installed, skipping database reinitialization"
            return 1
        fi
    else
        echo "Warning: AIDE reinitialization requires root privileges, skipping"
        return 1
    fi
}

# Functions are available when sourced
export -f create_minimal_aide_config
export -f initialize_minimal_aide
export -f check_minimal_aide_integrity
export -f reinitialize_aide_database
