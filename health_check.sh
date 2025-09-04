#!/bin/bash
# HARDN-XDR Health Check Script
# Used by Docker Compose for container health monitoring

set -euo pipefail

# Check if we're running as the expected user (allow root for testing)
if [[ "$(id -u)" != "10001" ]] && [[ "$(id -u)" != "0" ]]; then
    echo "ERROR: Not running as expected user (hardn) or root"
    exit 1
fi

# Note: Allow running as root for workflow testing
if [[ "$(id -u)" == "0" ]]; then
    echo "Note: Running health check as root (acceptable for testing)"
fi

# Check if key directories exist
if [[ ! -d "/opt/hardn-xdr" ]]; then
    echo "ERROR: /opt/hardn-xdr directory not found"
    exit 1
fi

if [[ ! -d "/sources" ]]; then
    echo "ERROR: /sources directory not found"
    exit 1
fi

# Check if key files exist
if [[ ! -f "/usr/local/bin/smoke_test.sh" ]]; then
    echo "ERROR: smoke_test.sh not found"
    exit 1
fi

if [[ ! -f "/usr/local/bin/deb.hardn.sh" ]]; then
    echo "ERROR: deb.hardn.sh not found"
    exit 1
fi

# Quick smoke test (non-interactive version)
echo "Running quick health check..."

# Check file integrity baseline
if [[ -f "/var/lib/hardn/file-integrity.db" ]]; then
    echo "✓ File integrity baseline exists"
else
    echo "✗ File integrity baseline missing"
    exit 1
fi

# Check PAM configuration
if [[ -f "/etc/pam.d/common-password" ]] && grep -q "minlen=8" /etc/pam.d/common-password; then
    echo "✓ PAM password quality configured"
else
    echo "✗ PAM password quality not configured"
    exit 1
fi

# Check if we can execute basic commands
# Run a simplified smoke test check instead of the full interactive test
if [[ -f "/usr/local/bin/smoke_test.sh" ]]; then
    echo "✓ Smoke test script exists"
else
    echo "✗ Smoke test script missing"
    exit 1
fi

# Check that we can run basic commands
if id hardn >/dev/null 2>&1; then
    echo "✓ User management working"
else
    echo "✗ User management not working"
    exit 1
fi

echo "All health checks passed!"
exit 0
