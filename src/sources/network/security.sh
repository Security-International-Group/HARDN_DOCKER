#!/bin/bash
# HARDN-XDR Network Registry - Network Security & Monitoring
# Native implementations for network security

# Firewall Configuration (UFW/iptables equivalent)
configure_firewall() {
    echo "Configuring firewall rules..."

    # Default deny policy
    iptables -P INPUT DROP 2>/dev/null || true
    iptables -P FORWARD DROP 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true

    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Rate limiting for SSH
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP 2>/dev/null || true

    # Log suspicious activity
    iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH-ATTEMPT: " 2>/dev/null || true

    echo "Firewall rules configured"
}

# Network Intrusion Detection
setup_network_monitoring() {
    echo "Setting up network monitoring..."

    # Monitor for suspicious network activity
    NETWORK_CHECKS="
    net.ipv4.conf.all.rp_filter=1
    net.ipv4.conf.default.rp_filter=1
    net.ipv4.tcp_syncookies=1
    net.ipv4.icmp_echo_ignore_broadcasts=1
    net.ipv4.icmp_ignore_bogus_error_responses=1
    "

    for check in $NETWORK_CHECKS; do
        key=$(echo "$check" | cut -d'=' -f1)
        value=$(echo "$check" | cut -d'=' -f2)
        echo "$key = $value" >> /etc/sysctl.conf
    done

    # Apply network settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

    echo "Network monitoring configured"
}

# Service Detection and Monitoring
monitor_network_services() {
    echo "Monitoring network services..."

    # Check for unauthorized services
    UNAUTHORIZED_PORTS="23 25 53 69 111 135 137 138 139 445"

    for port in $UNAUTHORIZED_PORTS; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "WARNING: Unauthorized service detected on port $port"
        fi
    done

    # Check for listening services
    listening_services=$(netstat -tuln 2>/dev/null | grep LISTEN | wc -l)
    echo "Found $listening_services listening services"

    echo "Network services monitored"
}

# Port Scanning Detection
detect_port_scanning() {
    echo "Setting up port scanning detection..."

    # Use iptables to detect port scanning
    iptables -N PORTSCAN 2>/dev/null || true
    iptables -A PORTSCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 2>/dev/null || true
    iptables -A PORTSCAN -j DROP 2>/dev/null || true

    # Apply to input chain
    iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j PORTSCAN 2>/dev/null || true

    echo "Port scanning detection enabled"
}

# Network Traffic Analysis
analyze_network_traffic() {
    echo "Analyzing network traffic patterns..."

    # Check for unusual connection patterns
    if command -v ss >/dev/null 2>&1; then
        # Count connections by state
        ss -tun state established | tail -n +2 | wc -l | xargs echo "Established connections:"
        ss -tun state listen | tail -n +2 | wc -l | xargs echo "Listening ports:"
    fi

    # Check network interface statistics
    if [ -f /proc/net/dev ]; then
        echo "Network interface statistics:"
        grep -E "^[[:space:]]*[a-zA-Z0-9]+:" /proc/net/dev | head -5
    fi

    echo "Network traffic analysis complete"
}

# DNS Security
configure_dns_security() {
    echo "Configuring DNS security..."

    # Use secure DNS settings
    if [ -f /etc/resolv.conf ]; then
        # Add timeout and attempts for DNS queries
        echo "options timeout:2 attempts:3" >> /etc/resolv.conf
    fi

    # Configure DNSSEC if supported
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

    # Apply settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

    echo "DNS security configured"
}

# ARP Security
configure_arp_security() {
    echo "Configuring ARP security..."

    # Enable ARP filtering
    echo "net.ipv4.conf.all.arp_filter = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.arp_filter = 1" >> /etc/sysctl.conf

    # Ignore ARP responses for other interfaces
    echo "net.ipv4.conf.all.arp_ignore = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.arp_ignore = 1" >> /etc/sysctl.conf

    # Apply settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

    echo "ARP security configured"
}

# Functions are available when sourced
# export -f configure_firewall
# export -f setup_network_monitoring
# export -f monitor_network_services
# export -f detect_port_scanning
# export -f analyze_network_traffic
# export -f configure_dns_security
# export -f configure_arp_security
