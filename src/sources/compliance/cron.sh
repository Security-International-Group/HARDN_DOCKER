#!/bin/bash
# Debian, Docker, Ruby and Dep's
# Run biweekly: 0 2 1,15 * * 

set -euo pipefail
IFS=$'\n\t'

LOG_FILE="/opt/hardn-xdr/state/hardn-cron.log"
LOCK_FILE="/opt/hardn-xdr/state/hardn-cron.lock"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE" 2>/dev/null || echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" 
}
log_error() { 
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${RED}ERROR:${NC} $*" >&2 | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${RED}ERROR:${NC} $*" >&2
}
log_success() { 
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${GREEN}SUCCESS:${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${GREEN}SUCCESS:${NC} $*" 
}
log_warning() { 
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${YELLOW}WARNING:${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${YELLOW}WARNING:${NC} $*" 
}
log_info() { 
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${BLUE}INFO:${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${BLUE}INFO:${NC} $*" 
}

setup_lock() {
    [ -f "$LOCK_FILE" ] && [ "$(($(date +%s) - $(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)))" -lt 3600 ] && { log_error "Lock file exists"; exit 1; } || rm -f "$LOCK_FILE"
    touch "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
}

check_root() { [ $EUID -ne 0 ] && { log_error "Must run as root"; exit 1; }; }

update_debian() {
    log_info "Updating Debian packages..."
    apt-get update --error-on=any || { log_error "Update failed"; return 1; }
    SECURITY_UPDATES=$(apt-get --just-print upgrade | grep -c "^Inst.*security" || true)
    [ "$SECURITY_UPDATES" -gt 0 ] && log_warning "$SECURITY_UPDATES security updates"
    apt-get upgrade -y --with-new-pkgs=no || { log_error "Upgrade failed"; return 1; }
    apt-get autoremove -y && apt-get autoclean && apt-get clean
    log_success "Debian updates done"
}

update_docker() {
    log_info "Updating Docker..."
    command -v docker >/dev/null 2>&1 || { log_warning "Docker not found"; return 0; }
    [ -f "$PROJECT_ROOT/docker-compose.yml" ] && cd "$PROJECT_ROOT" && docker-compose pull || log_warning "Pull failed"
    docker system prune -f >/dev/null 2>&1 || true
    docker image prune -f >/dev/null 2>&1 || true
    log_success "Docker updates done"
}

update_ruby() {
    log_info "Updating Ruby gems..."
    command -v ruby >/dev/null 2>&1 || { log_warning "Ruby not found"; return 0; }
    [ -f "$PROJECT_ROOT/Gemfile" ] && command -v bundle >/dev/null 2>&1 && cd "$PROJECT_ROOT" && bundle update || log_warning "Bundle update failed"
    command -v gem >/dev/null 2>&1 && gem update --system || log_warning "Gem update failed"
    log_success "Ruby updates done"
}

run_scans() {
    log_info "Running scans..."
    command -v docker >/dev/null 2>&1 && docker scout --help >/dev/null 2>&1 && [ -f "$PROJECT_ROOT/Dockerfile" ] && cd "$PROJECT_ROOT" && docker scout cves Dockerfile || log_warning "Scout failed"
    command -v lynis >/dev/null 2>&1 && lynis audit system --quiet --no-colors || log_warning "Lynis failed"
    command -v oscap >/dev/null 2>&1 && log_info "OpenSCAP available (needs config)" || log_warning "OpenSCAP not found"
}

check_files() {
    log_info "Checking project files..."
    cd "$PROJECT_ROOT"
    grep -r "password\|secret\|key" --include="*.sh" --include="*.py" --include="*.rb" . 2>/dev/null | grep -v ".*=" >/dev/null && log_warning "Potential secrets found"
    WORLD_WRITABLE=$(find . -type f -perm -002 2>/dev/null | wc -l)
    [ "$WORLD_WRITABLE" -gt 0 ] && log_warning "$WORLD_WRITABLE world-writable files"
    [ -f "package.json" ] && command -v npm >/dev/null 2>&1 && npm audit --audit-level=moderate >/dev/null 2>&1 || log_warning "NPM audit issues"
    log_success "File checks done"
}

update_tools() {
    log_info "Updating security tools..."
    command -v freshclam >/dev/null 2>&1 && freshclam || log_warning "Freshclam failed"
    command -v rkhunter >/dev/null 2>&1 && rkhunter --update || log_warning "Rkhunter failed"
    command -v aide >/dev/null 2>&1 && [ -f /var/lib/aide/aide.db ] && aide --check --config=/etc/aide/aide.conf || log_warning "AIDE failed"
    log_success "Tools updated"
}

generate_report() {
    log_info "Generating report..."
    REPORT_FILE="/opt/hardn-xdr/state/hardn-compliance-report-$(date +%Y%m%d).txt"
    {
        echo "HARDN-XDR Compliance Report"
        echo "Generated: $(date)"
        echo "=========================="
        echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
        echo "Kernel: $(uname -r)"
        echo "Uptime: $(uptime -p)"
        echo "Security updates: $(apt-get --just-print upgrade 2>/dev/null | grep -c "^Inst.*security" || echo 'Unknown')"
        echo "Tools: ClamAV($(command -v clamscan >/dev/null 2>&1 && echo 'Yes' || echo 'No')), rkhunter($(command -v rkhunter >/dev/null 2>&1 && echo 'Yes' || echo 'No')), etc."
    } > "$REPORT_FILE"
    log_success "Report: $REPORT_FILE"
}

send_notification() {
    log_info "Sending notification..."
    # Add email/webhook logic if needed
}

main() {
    log_info "Starting compliance cron"
    setup_lock
    check_root
    update_debian
    update_docker
    update_ruby
    run_scans
    check_files
    update_tools
    generate_report
    send_notification
    log_success "Completed"
}

main "$@"
