#!/usr/bin/env bash
# HARDN-XDR OpenSCAP Registry - Security Content Automation Protocol (wrapper)

set -euo pipefail

OPENVSCAP_PROFILES="
cis: CIS Docker Benchmark
stig: DISA STIG for Linux
usgcb: US Government Configuration Baseline
"

ok(){ echo "PASS: $*"; }
fail(){ echo "FAIL: $*"; }
warn(){ echo "WARN: $*"; }

is_apparmor_active() {
  # kernel support?
  if [[ -f /sys/module/apparmor/parameters/enabled ]] && grep -q '[Yy]' /sys/module/apparmor/parameters/enabled 2>/dev/null; then
    # profile for this process
    local cur="unconfined"
    cur=$(cat /proc/self/attr/current 2>/dev/null || echo "unconfined")
    [[ "$cur" != "unconfined" && -n "$cur" ]]
  else
    return 1
  fi
}

is_nonewprivs_set() {
  grep -Eq '^NoNewPrivs:\s*1$' /proc/self/status 2>/dev/null
}

trusted_base_image() {
  # prefer /etc/os-release
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:+ $ID_LIKE}" in
      *debian*|*ubuntu*|*debian*ubuntu*) return 0 ;;
    esac
  fi
  return 1
}

# --- CIS Docker Benchmark checks ---------------------------------------------
cis_docker_checks() {
  echo "Running CIS Docker Benchmark checks (OpenSCAP-style)..."
  local passed=0 failed=0

  # 4.1: dedicated user exists
  if id hardn >/dev/null 2>&1; then ok "CIS 4.1 - Non-root user exists"; ((passed++))
  else fail "CIS 4.1 - Non-root user missing"; ((failed++)); fi

  # 4.2: trusted base image
  if trusted_base_image; then ok "CIS 4.2 - Trusted base image"; ((passed++))
  else fail "CIS 4.2 - Untrusted base image"; ((failed++)); fi

  # 5.1: AppArmor
  if is_apparmor_active; then ok "CIS 5.1 - AppArmor enabled"; ((passed++))
  else
    if [[ "${HARDN_ALLOW_UNCONFINED:-0}" == "1" ]]; then warn "CIS 5.1 - AppArmor not active (allowed in CI)"; else fail "CIS 5.1 - AppArmor not active"; ((failed++)); fi
  fi

  # 5.4: non-root
  if [[ "$(id -u)" != "0" ]]; then ok "CIS 5.4 - Non-privileged execution"; ((passed++))
  else
    if [[ "${HARDN_ALLOW_ROOT:-0}" == "1" ]]; then warn "CIS 5.4 - Running as root (allowed in CI)"; else fail "CIS 5.4 - Running as root"; ((failed++)); fi
  fi

  # 5.25: NoNewPrivs
  if is_nonewprivs_set; then ok "CIS 5.25 - NoNewPrivs set"; ((passed++))
  else fail "CIS 5.25 - NoNewPrivs not set"; ((failed++)); fi

  echo "CIS Docker Benchmark: $passed passed, $failed failed"
  # return number of failures (0 == pass)
  return $failed
}


disa_stig_checks() {
  echo "Running DISA STIG checks (OpenSCAP-style)..."
  local passed=0 failed=0

  # system accounts non-login (uid<1000)
  local non_login_accounts
  non_login_accounts=$(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false"){print}' /etc/passwd | wc -l)
  if [[ "$non_login_accounts" -eq 0 ]]; then ok "STIG - System accounts properly configured"; ((passed++))
  else fail "STIG - $non_login_accounts system accounts allow login"; ((failed++)); fi

  # no empty password fields
  local empty_passwords
  empty_passwords=$(awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow 2>/dev/null | wc -l || echo 0)
  if [[ "$empty_passwords" -eq 0 ]]; then ok "STIG - No empty password fields"; ((passed++))
  else fail "STIG - $empty_passwords accounts have empty/locked passwords"; ((failed++)); fi

  # only root has UID 0
  local uid_zero_accounts
  uid_zero_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)
  if [[ "$uid_zero_accounts" -eq 1 ]]; then ok "STIG - Only root has UID 0"; ((passed++))
  else fail "STIG - $uid_zero_accounts accounts have UID 0"; ((failed++)); fi

  echo "DISA STIG: $passed passed, $failed failed"
  return $failed
}


generate_scap_report() {
  echo "Generating SCAP-compliant security report..."
  local REPORT_FILE="/var/lib/hardn/openscap-report.xml"
  mkdir -p /var/lib/hardn


  local os_name
  if command -v lsb_release >/dev/null 2>&1; then
    os_name="$(lsb_release -d | cut -f2)"
  elif [[ -r /etc/os-release ]]; then
    . /etc/os-release; os_name="${PRETTY_NAME:-Linux}"
  else
    os_name="Linux"
  fi

  cat > "$REPORT_FILE" <<EOF
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
              <oval:os_name>${os_name}</oval:os_name>
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

# --- Orchestration -----------------------------------------------------------
run_security_assessment() {
  echo "Running comprehensive security assessment (OpenSCAP-style)..."

  echo "=== CIS Docker Benchmark Assessment ==="
  cis_docker_checks; local cis_result=$?

  echo
  echo "=== DISA STIG Assessment ==="
  disa_stig_checks; local stig_result=$?

  echo
  echo "=== Generating SCAP Report ==="
  generate_scap_report

  if [[ $cis_result -eq 0 && $stig_result -eq 0 ]]; then
    echo "SECURITY ASSESSMENT: PASSED"; return 0
  else
    echo "SECURITY ASSESSMENT: FAILED"; return 1
  fi
}

echo "Available OpenSCAP profiles:"
printf '  - %s\n' $OPENVSCAP_PROFILES

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "HARDN-XDR OpenSCAP Registry Setup"
  echo "================================="
  cis_docker_checks
  disa_stig_checks
  generate_scap_report
  run_security_assessment
  echo; echo "OpenSCAP registry configuration completed."
fi