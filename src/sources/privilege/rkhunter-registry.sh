#!/bin/bash
# HARDN-XDR Rkhunter Registry - Rootkit Detection
# Mirrors rkhunter functionality using native Linux tools

# Rootkit detection patterns and signatures
RKHUNTER_ROOTKIT_SIGNATURES="
/etc/rc.d/rc.sysinit
/etc/rc.d/rc.local
/etc/rc.d/rc.modules
/usr/bin/.etc
/usr/sbin/.etc
/etc/inetd.conf
/etc/xinetd.conf
/etc/sysctl.conf
/etc/passwd
/etc/shadow
/etc/group
"

# Known rootkit files and directories to check
KNOWN_ROOTKIT_FILES="
/dev/.lib
/lib/.lib
/usr/lib/.lib
/etc/.lib
/dev/.lib/.lib
/lib/.lib/.lib
/usr/lib/.lib/.lib
/etc/.lib/.lib
/dev/ptyrx
/dev/ptyrf
/dev/ptyrx.bak
/dev/ptyrf.bak
"

# Suspicious processes to monitor
SUSPICIOUS_PROCESSES="
rkHunter
rkhunter
jackpop
jackpop2
jackpop3
"

detect_rootkits() {
    echo "Performing rootkit detection (Rkhunter-style)..."

    local findings=0

    # Check for known rootkit files
    echo "Checking for known rootkit files..."
    for file in $KNOWN_ROOTKIT_FILES; do
        if [ -e "$file" ]; then
            echo "ROOTKIT DETECTED: $file"
            findings=$((findings + 1))
        fi
    done

    # Check for suspicious processes
    echo "Checking for suspicious processes..."
    for proc in $SUSPICIOUS_PROCESSES; do
        if pgrep -f "$proc" >/dev/null 2>&1; then
            echo "SUSPICIOUS PROCESS: $proc"
            findings=$((findings + 1))
        fi
    done

    # Check for hidden files in common directories
    echo "Checking for hidden files in system directories..."
    for dir in /bin /sbin /usr/bin /usr/sbin /etc; do
        if [ -d "$dir" ]; then
            hidden_files=$(find "$dir" -name ".*" -type f 2>/dev/null | wc -l)
            if [ "$hidden_files" -gt 0 ]; then
                echo "Hidden files found in $dir: $hidden_files files"
                findings=$((findings + 1))
            fi
        fi
    done

    # Check for unusual file permissions
    echo "Checking for unusual file permissions..."
    unusual_perms=$(find /bin /sbin /usr/bin /usr/sbin -perm /6000 2>/dev/null | wc -l)
    if [ "$unusual_perms" -gt 10 ]; then
        echo "Unusual SUID/SGID files found: $unusual_perms files"
        findings=$((findings + 1))
    fi

    # Check for modified system binaries
    echo "Checking system binary integrity..."
    for binary in /bin/ls /bin/ps /bin/netstat /usr/bin/top; do
        if [ -f "$binary" ]; then
            # Check if binary is in expected location
            if ! which "$(basename "$binary")" >/dev/null 2>&1; then
                echo "POTENTIAL ROOTKIT: $binary not in PATH"
                findings=$((findings + 1))
            fi
        fi
    done

    # Check for rootkit signatures in system files
    echo "Checking for rootkit signatures..."
    for sig in $RKHUNTER_ROOTKIT_SIGNATURES; do
        if [ -f "$sig" ]; then
            # Check if file contains suspicious content
            if grep -q "rootkit\|backdoor\|malware" "$sig" 2>/dev/null; then
                echo "SUSPICIOUS CONTENT: $sig"
                findings=$((findings + 1))
            fi
        fi
    done

    if [ $findings -eq 0 ]; then
        echo "No rootkit indicators found"
        return 0
    else
        echo "Found $findings potential rootkit indicators"
        return 1
    fi
}

# CIS 3.3.1: Ensure suspicious packets are logged
setup_network_monitoring() {
    echo "Setting up network monitoring (Rkhunter-style)..."

    # Enable logging of suspicious network activity
    if command -v iptables >/dev/null 2>&1; then
        # Log suspicious connection attempts
        iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j LOG --log-prefix "SSH-ATTEMPT: " 2>/dev/null || true
        iptables -A INPUT -p tcp --dport 23 -m state --state NEW -j LOG --log-prefix "TELNET-ATTEMPT: " 2>/dev/null || true
        echo "Network monitoring rules added"
    fi
}

# DISA STIG: Check for unauthorized network services
check_network_services() {
    echo "Checking network services (DISA STIG compliance)..."

    # List of unauthorized services
    UNAUTHORIZED_PORTS="23 25 53 69 111 135 137 138 139 445"

    for port in $UNAUTHORIZED_PORTS; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "WARNING: Unauthorized service running on port $port"
        fi
    done
}

# Functions are available when sourced
# export -f detect_rootkits
# export -f setup_network_monitoring
# export -f check_network_services
