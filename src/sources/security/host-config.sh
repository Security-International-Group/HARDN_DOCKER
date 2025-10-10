#!/bin/bash
# HARDN-XDR Host Configuration Security
# Configure host-level security for Docker compliance

# Function to configure auditing
configure_auditing() {
    echo "Configuring system auditing..."

    # Install auditd if not present
    if ! command -v auditctl >/dev/null 2>&1; then
        apt-get update --quiet && apt-get install -y --no-install-recommends auditd audispd-plugins
    fi

    # Configure audit rules for Docker
    cat > /etc/audit/rules.d/docker.rules << 'EOF'
# Docker audit rules
-w /usr/bin/docker -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /usr/lib/systemd/system/docker.socket -k docker
-w /etc/default/docker -k docker
-w /etc/docker/daemon.json -k docker
-w /usr/bin/docker-containerd -k docker
-w /usr/bin/docker-runc -k docker
-w /var/run/docker.sock -k docker
EOF

    # Configure audit rules for system security
    cat > /etc/audit/rules.d/system.rules << 'EOF'
# System audit rules
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d -p wa -k identity
-w /var/log/auth.log -p wa -k logins
-w /var/log/sudo.log -p wa -k sudo
EOF

    # Reload audit rules
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -R /etc/audit/rules.d/docker.rules 2>/dev/null || true
        auditctl -R /etc/audit/rules.d/system.rules 2>/dev/null || true
    fi

    # Enable and start auditd
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true

    echo "System auditing configured"
}

# Function to configure TLS authentication
configure_tls_auth() {
    echo "Configuring TLS authentication..."

    # Create TLS directory
    mkdir -p /etc/ssl/docker

    # Generate CA certificate
    if [[ ! -f /etc/ssl/docker/ca.pem ]]; then
        openssl genrsa -out /etc/ssl/docker/ca-key.pem 4096 2>/dev/null || true
        openssl req -new -x509 -days 365 -key /etc/ssl/docker/ca-key.pem \
            -out /etc/ssl/docker/ca.pem \
            -subj "/C=US/ST=State/L=City/O=HARDN/CN=Docker-CA" 2>/dev/null || true
    fi

    # Generate client certificate
    if [[ ! -f /etc/ssl/docker/client-cert.pem ]]; then
        openssl genrsa -out /etc/ssl/docker/client-key.pem 4096 2>/dev/null || true
        openssl req -subj "/CN=docker-client" -new -key /etc/ssl/docker/client-key.pem \
            -out /etc/ssl/docker/client.csr 2>/dev/null || true

        cat > /etc/ssl/docker/client-ext.cnf << 'EOF'
[client]
extendedKeyUsage = clientAuth
EOF

        openssl x509 -req -days 365 -in /etc/ssl/docker/client.csr \
            -CA /etc/ssl/docker/ca.pem -CAkey /etc/ssl/docker/ca-key.pem \
            -out /etc/ssl/docker/client-cert.pem \
            -extfile /etc/ssl/docker/client-ext.cnf -extensions client 2>/dev/null || true
    fi

    # Set proper permissions
    chmod 600 /etc/ssl/docker/*-key.pem
    chmod 644 /etc/ssl/docker/ca.pem /etc/ssl/docker/*-cert.pem

    echo "TLS authentication configured"
}

# Function to configure user namespace
configure_user_namespace() {
    echo "Configuring user namespace..."

    # Create subuid and subgid files for rootless containers
    if [[ ! -f /etc/subuid ]]; then
        echo "root:100000:65536" > /etc/subuid
    fi

    if [[ ! -f /etc/subgid ]]; then
        echo "root:100000:65536" > /etc/subgid
    fi

    # Configure userns-remap in Docker
    if [[ -f /etc/docker/daemon.json ]]; then
        # Add userns-remap if not present
        if ! grep -q "userns-remap" /etc/docker/daemon.json; then
            sed -i 's/}/,\n  "userns-remap": "default"\n}/' /etc/docker/daemon.json
        fi
    fi

    echo "User namespace configured"
}

# Function to configure centralized logging
configure_centralized_logging() {
    echo "Configuring centralized logging..."

    # Install rsyslog if not present
    if ! command -v rsyslogd >/dev/null 2>&1; then
        apt-get install -y --no-install-recommends rsyslog
    fi

    # Configure rsyslog for Docker logging
    cat > /etc/rsyslog.d/docker.conf << 'EOF'
# Docker logging configuration
$template DockerLogFormat,"%TIMESTAMP% %HOSTNAME% docker[%PROCID%]: %msg%\n"

if $programname == 'dockerd' then /var/log/docker/dockerd.log;DockerLogFormat
if $programname == 'docker-containerd' then /var/log/docker/containerd.log;DockerLogFormat
& stop
EOF

    # Create log directory
    mkdir -p /var/log/docker
    chmod 755 /var/log/docker

    # Enable and start rsyslog
    systemctl enable rsyslog 2>/dev/null || true
    systemctl start rsyslog 2>/dev/null || true

    echo "Centralized logging configured"
}

# Function to configure live restore
configure_live_restore() {
    echo "Configuring Docker live restore..."

    # Add live-restore to daemon.json if not present
    if [[ -f /etc/docker/daemon.json ]]; then
        if ! grep -q "live-restore" /etc/docker/daemon.json; then
            sed -i 's/}/,\n  "live-restore": true\n}/' /etc/docker/daemon.json
        fi
    fi

    echo "Live restore configured"
}

# Function to disable userland proxy
configure_userland_proxy() {
    echo "Disabling Docker userland proxy..."

    # Add userland-proxy setting to daemon.json
    if [[ -f /etc/docker/daemon.json ]]; then
        if ! grep -q "userland-proxy" /etc/docker/daemon.json; then
            sed -i 's/}/,\n  "userland-proxy": false\n}/' /etc/docker/daemon.json
        fi
    fi

    echo "Userland proxy disabled"
}

# Function to verify host configuration
verify_host_config() {
    echo "Verifying host configuration..."

    # Check auditd
    if systemctl is-active --quiet auditd 2>/dev/null; then
        echo "✓ Auditd is running"
    else
        echo "✗ Auditd is not running"
    fi

    # Check TLS certificates
    if [[ -f /etc/ssl/docker/ca.pem ]] && [[ -f /etc/ssl/docker/client-cert.pem ]]; then
        echo "✓ TLS certificates exist"
    else
        echo "✗ TLS certificates missing"
    fi

    # Check user namespace
    if [[ -f /etc/subuid ]] && [[ -f /etc/subgid ]]; then
        echo "✓ User namespace configured"
    else
        echo "✗ User namespace not configured"
    fi

    # Check centralized logging
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        echo "✓ Centralized logging configured"
    else
        echo "✗ Centralized logging not configured"
    fi
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Host Configuration Security Setup"
    echo "==========================================="

    configure_auditing
    configure_tls_auth
    configure_user_namespace
    configure_centralized_logging
    configure_live_restore
    configure_userland_proxy
    verify_host_config

    echo ""
    echo "Host configuration security setup completed."
fi
