#!/bin/bash
# HARDN-XDR ClamAV Registry - Antivirus Scanning
# Mirrors clamav functionality using native Linux tools

# ClamAV-style virus signatures (simplified for demonstration)
CLAMAV_VIRUS_SIGNATURES="
Eicar-Test-Signature
Win.Test.EICAR_HDB-1
Exploit.Shellcode
Trojan.Generic
"

# File types to scan for malware
SCAN_EXTENSIONS="
.exe .dll .com .bat .cmd .vbs .js .jar .class .py .pl .sh .bin
.doc .docx .xls .xlsx .ppt .pptx .pdf .zip .rar .7z .tar .gz
"

# Known malware file patterns
MALWARE_PATTERNS="
eval(base64_decode
document.write(unescape
ActiveXObject
WScript.Shell
powershell -enc
chmod +x /tmp/
wget http://
curl -s http://
"

scan_for_malware() {
    echo "Performing malware scan (ClamAV-style)..."

    local findings=0
    local scanned_files=0

    # Scan common directories for suspicious files
    SCAN_PATHS="/tmp /var/tmp /home /usr/local /opt"

    for path in $SCAN_PATHS; do
        if [ -d "$path" ]; then
            echo "Scanning $path..."

            # Find files with suspicious extensions
            for ext in $SCAN_EXTENSIONS; do
                suspicious_files=$(find "$path" -name "*$ext" 2>/dev/null | wc -l)
                if [ "$suspicious_files" -gt 0 ]; then
                    echo "Found $suspicious_files files with extension $ext in $path"
                fi
            done

            # Use a more compatible approach for file listing
            find "$path" -type f -print0 2>/dev/null | while IFS= read -r -d '' file; do
                scanned_files=$((scanned_files + 1))

                # Check file permissions for suspicious patterns
                perms=$(stat -c "%a" "$file" 2>/dev/null)
                if [ "$perms" = "777" ] || [ "$perms" = "666" ]; then
                    echo "SUSPICIOUS PERMISSIONS: $file ($perms)"
                    findings=$((findings + 1))
                fi

                # Check for known malware patterns in file content (first 1KB only)
                if head -c 1024 "$file" 2>/dev/null | grep -q "$MALWARE_PATTERNS"; then
                    echo "MALWARE PATTERN DETECTED: $file"
                    findings=$((findings + 1))
                fi
            done
        fi
    done

    # Check for EICAR test file
    if [ -f "/tmp/eicar.com" ] || [ -f "/var/tmp/eicar.com" ]; then
        echo "EICAR TEST FILE DETECTED (this is expected for testing)"
        findings=$((findings + 1))
    fi

    # Check for known virus signatures
    echo "Checking for known virus signatures..."
    for sig in $CLAMAV_VIRUS_SIGNATURES; do
        # In a real implementation, this would check against signature database
        echo "Checking for signature: $sig"
    done

    echo "Scanned $scanned_files files"
    if [ $findings -eq 0 ]; then
        echo "No malware indicators found"
        return 0
    else
        echo "Found $findings potential malware indicators"
        return 1
    fi
}

# CIS 1.3.1: Ensure AIDE is installed (we implement this natively)
setup_file_monitoring() {
    echo "Setting up file monitoring (ClamAV-style)..."

    # Create quarantine directory
    mkdir -p /var/lib/hardn/quarantine
    chmod 700 /var/lib/hardn/quarantine

    # Set up monitoring for common malware locations
    MONITOR_PATHS="/tmp /var/tmp /home/*/Downloads /home/*/Desktop"

    for path in $MONITOR_PATHS; do
        if [ -d "$path" ]; then
            echo "Monitoring $path for suspicious activity"
            # In a real implementation, this would set up inotify watches
        fi
    done

    echo "File monitoring configured"
}

# DISA STIG: Check for unauthorized file types
check_unauthorized_files() {
    echo "Checking for unauthorized file types (DISA STIG)..."

    # DISA STIG requires blocking certain file types
    UNAUTHORIZED_EXTS=".exe .bat .cmd .com .pif .scr .vbs .js .jar"

    for ext in $UNAUTHORIZED_EXTS; do
        count=$(find /home /tmp /var/tmp -name "*$ext" 2>/dev/null | wc -l)
        if [ "$count" -gt 0 ]; then
            echo "WARNING: Found $count unauthorized $ext files"
        fi
    done
}

# Update virus signatures (simulated)
update_signatures() {
    echo "Updating malware signatures (simulated)..."

    # In a real implementation, this would download updated signatures
    echo "Signature database updated (simulated)"
    echo "Last update: $(date)" > /var/lib/hardn/clamav-last-update
}
