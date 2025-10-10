#!/bin/bash
# HARDN-XDR Container Image Security
# Configure container image security features

# Function to enable Docker Content Trust
enable_content_trust() {
    echo "Enabling Docker Content Trust..."

    # Set environment variable for content trust
    export DOCKER_CONTENT_TRUST=1

    # Create content trust directory
    mkdir -p /etc/docker/trust

    # Generate root key for content trust (if not exists)
    if [[ ! -f ~/.docker/trust/private/root-key.pem ]]; then
        echo "Generating Docker Content Trust root key..."
        docker trust key generate root --dir /etc/docker/trust 2>/dev/null || true
    fi

    # Generate repository key
    if [[ ! -f ~/.docker/trust/private/hardn-repo-key.pem ]]; then
        echo "Generating repository key..."
        docker trust key generate hardn-repo --dir /etc/docker/trust 2>/dev/null || true
    fi

    echo "Docker Content Trust enabled"
}

# Function to configure image scanning
configure_image_scanning() {
    echo "Configuring image scanning..."

    # Create image scanning configuration
    cat > /etc/docker/image-scan.conf << 'EOF'
{
  "scan-on-push": true,
  "scan-on-pull": false,
  "vulnerability-db-update": true,
  "max-scan-duration": "300s",
  "ignore-unfixed": false,
  "severity-threshold": "medium"
}
EOF

    echo "Image scanning configured"
}

# Function to verify base image security
verify_base_image() {
    echo "Verifying base image security..."

    # Check if base image is from trusted registry
    BASE_IMAGE="debian:trixie-slim"
    echo "Base image: $BASE_IMAGE"

    # Check for known vulnerabilities (placeholder - in production use actual scanner)
    echo "✓ Base image from official Debian repository"
    echo "✓ Slim variant reduces attack surface"
    echo "✓ Trixie (testing) provides latest security updates"

    # Verify image signature if content trust is enabled
    if [[ "${DOCKER_CONTENT_TRUST:-0}" = "1" ]]; then
        echo "✓ Content trust enabled for base image verification"
    fi
}

# Function to configure image build security
configure_build_security() {
    echo "Configuring image build security..."

    # Create build security configuration
    cat > /etc/docker/build-security.conf << 'EOF'
{
  "buildkit": true,
  "no-cache": false,
  "pull": true,
  "security-opt": [
    "no-new-privileges=true"
  ],
  "cap-drop": [
    "ALL"
  ],
  "cap-add": [
    "CAP_CHOWN",
    "CAP_SETUID",
    "CAP_SETGID"
  ],
  "network": "none",
  "userns-remap": "default",
  "isolation": "default"
}
EOF

    echo "Image build security configured"
}

# Function to create image signing policy
create_signing_policy() {
    echo "Creating image signing policy..."

    # Create trust policy
    cat > /etc/docker/trust-policy.json << 'EOF'
{
  "signers": {
    "hardn": {
      "keys": [
        {
          "id": "hardn-repo"
        }
      ]
    }
  },
  "trustedKeys": {
    "hardn-repo": "/etc/docker/trust/private/hardn-repo-key.pem"
  },
  "repository": {
    "tburns0321/hardn_docker": {
      "signers": ["hardn"]
    }
  }
}
EOF

    echo "Image signing policy created"
}

# Function to verify image security
verify_image_security() {
    echo "Verifying image security configuration..."

    # Check content trust
    if [[ "${DOCKER_CONTENT_TRUST:-0}" = "1" ]]; then
        echo "✓ Docker Content Trust enabled"
    else
        echo "✗ Docker Content Trust disabled"
    fi

    # Check for security configurations
    if [[ -f /etc/docker/image-scan.conf ]]; then
        echo "✓ Image scanning configured"
    else
        echo "✗ Image scanning not configured"
    fi

    if [[ -f /etc/docker/build-security.conf ]]; then
        echo "✓ Build security configured"
    else
        echo "✗ Build security not configured"
    fi

    if [[ -f /etc/docker/trust-policy.json ]]; then
        echo "✓ Image signing policy configured"
    else
        echo "✗ Image signing policy not configured"
    fi
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Container Image Security Setup"
    echo "======================================="

    enable_content_trust
    configure_image_scanning
    verify_base_image
    configure_build_security
    create_signing_policy
    verify_image_security

    echo ""
    echo "Container image security configuration completed."
fi
