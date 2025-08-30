#!/bin/bash
# HARDN-XDR OpenSCAP Registry - Security Content Automation Protocol
# Mirrors OpenSCAP functionality using native Linux tools

# OpenSCAP XCCDF profiles equivalent
OPENVSCAP_PROFILES="
cis: CIS Docker Benchmark
stig: DISA STIG for Linux
usgcb: US Government Configuration Baseline
"

# CIS Docker Benchmark checks (implemented natively)
cis_docker_checks() {
    echo "Running CIS Docker Benchmark checks (OpenSCAP-style)..."

    local passed=0
    local failed=0

    # CIS 4.1: Ensure a user for the container has been created
    if id hardn >/dev/null 2>&1; then
        echo "PASS: CIS 4.1 - Non-root user exists"
        passed=$((passed + 1))
    else
        echo "FAIL: CIS 4.1 - Non-root user missing"
        failed=$((failed + 1))
    fi

    # CIS 4.2: Ensure that containers use trusted base images
    if [ -f /etc/os-release ]; then
        if grep -q "Debian\|Ubuntu" /etc/os-release; then
            echo "PASS: CIS 4.2 - Trusted base image"
            passed=$((passed + 1))
        else
            echo "FAIL: CIS 4.2 - Untrusted base image"
            failed=$((failed + 1))
        fi
    fi

    # CIS 5.1: Ensure AppArmor Profile is Enabled
    if command -v apparmor_status >/dev/null 2>&1; then
        if apparmor_status 2>/dev/null | grep -q "profiles are loaded"; then
            echo "PASS: CIS 5.1 - AppArmor enabled"
            passed=$((passed + 1))
        else
            echo "FAIL: CIS 5.1 - AppArmor not active"
            failed=$((failed + 1))
        fi
    fi

    # CIS 5.4: Ensure privileged containers are not used
    if [ "$(id -u)" != "0" ]; then
        echo "PASS: CIS 5.4 - Non-privileged execution"
        passed=$((passed + 1))
    else
        echo "FAIL: CIS 5.4 - Running as root"
        failed=$((failed + 1))
    fi

    # CIS 5.25: Ensure container is restricted from acquiring additional privileges
    if grep -q "NoNewPrivs" /proc/$$/status 2>/dev/null; then
        echo "PASS: CIS 5.25 - NoNewPrivs set"
        passed=$((passed + 1))
    else
        echo "FAIL: CIS 5.25 - NoNewPrivs not set"
        failed=$((failed + 1))
    fi

    echo "CIS Docker Benchmark: $passed passed, $failed failed"
    return $failed
}

# DISA STIG checks (implemented natively)
disa_stig_checks() {
    echo "Running DISA STIG checks (OpenSCAP-style)..."

    local passed=0
    local failed=0

    # STIG RHEL-07-010010: Ensure system accounts are non-login
    non_login_accounts=$(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}' /etc/passwd | wc -l)
    if [ "$non_login_accounts" -eq 0 ]; then
        echo "PASS: STIG - System accounts properly configured"
        passed=$((passed + 1))
    else
        echo "FAIL: STIG - $non_login_accounts system accounts allow login"
        failed=$((failed + 1))
    fi

    # STIG RHEL-07-010020: Ensure password fields are not empty
    empty_passwords=$(awk -F: '($2 == "") {print $1}' /etc/shadow | wc -l)
    if [ "$empty_passwords" -eq 0 ]; then
        echo "PASS: STIG - No empty password fields"
        passed=$((passed + 1))
    else
        echo "FAIL: STIG - $empty_passwords accounts have empty passwords"
        failed=$((failed + 1))
    fi

    # STIG RHEL-07-010030: Ensure root is the only UID 0 account
    uid_zero_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)
    if [ "$uid_zero_accounts" -eq 1 ]; then
        echo "PASS: STIG - Only root has UID 0"
        passed=$((passed + 1))
    else
        echo "FAIL: STIG - $uid_zero_accounts accounts have UID 0"
        failed=$((failed + 1))
    fi

    echo "DISA STIG: $passed passed, $failed failed"
    return $failed
}

# Generate SCAP-compliant report
generate_scap_report() {
    echo "Generating SCAP-compliant security report..."

    REPORT_FILE="/var/lib/hardn/openscap-report.xml"

    cat > "$REPORT_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1">
  <arf:assets>
    <arf:asset>
      <arf:asset-id>HARDN-XDR-Container</arf:asset-id>
      <arf:asset-type>container</arf:asset-type>
    </arf:asset>
  </arf:assets>
  <arf:reports>
    <arf:report>
      <arf:content>
        <oval:results xmlns:oval="http://oval.mitre.org/XMLSchema/oval-results-5">
          <oval:system>
            <oval:system-info>
              <oval:os_name>$(lsb_release -d 2>/dev/null | cut -f2 || echo "Linux")</oval:os_name>
              <oval:os_version>$(uname -r)</oval:os_version>
              <oval:architecture>$(uname -m)</oval:architecture>
            </oval:system-info>
          </oval:system>
        </oval:results>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
EOF

    echo "SCAP report generated: $REPORT_FILE"
}

# Run comprehensive security assessment
run_security_assessment() {
    echo "Running comprehensive security assessment (OpenSCAP-style)..."

    echo "=== CIS Docker Benchmark Assessment ==="
    cis_docker_checks
    cis_result=$?

    echo ""
    echo "=== DISA STIG Assessment ==="
    disa_stig_checks
    stig_result=$?

    echo ""
    echo "=== Generating SCAP Report ==="
    generate_scap_report

    # Overall assessment
    if [ $cis_result -eq 0 ] && [ $stig_result -eq 0 ]; then
        echo "SECURITY ASSESSMENT: PASSED"
        return 0
    else
        echo "SECURITY ASSESSMENT: FAILED"
        return 1
    fi
}

# Display available security profiles
echo "Available OpenSCAP profiles:"
for profile in $OPENVSCAP_PROFILES; do
    echo "  - $profile"
done

# Functions are available when sourced
# export -f cis_docker_checks
# export -f disa_stig_checks
# export -f generate_scap_report
# export -f run_security_assessment

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR OpenSCAP Registry Setup"
    echo "================================="

    cis_docker_checks
    disa_stig_checks
    generate_scap_report
    run_security_assessment

    echo ""
    echo "OpenSCAP registry configuration completed."
fi
