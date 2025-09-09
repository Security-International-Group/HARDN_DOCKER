#!/usr/bin/env bash

# This shell script it to automate building from the Dockerfile

set -euo pipefail  # Exit on error, undefined vars, and pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running with sudo privileges
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires sudo privileges to manage Docker containers."
        log_error "Please run with: sudo $0"
        exit 1
    fi
    log_info "Running with sudo privileges ✓"
}

# Check if Docker is installed and running
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or not accessible"
        log_error "Please start Docker service: sudo systemctl start docker"
        exit 1
    fi
    log_info "Docker is available and running ✓"
}

# Check if Dockerfile exists
check_dockerfile() {
    if [[ ! -f "Dockerfile" ]]; then
        log_error "Dockerfile not found in current directory"
        exit 1
    fi
    log_info "Dockerfile found ✓"
}

prep_build(){
    log_info "Starting prep_build function..."

    # Remove any previous container
    log_info "Removing existing hardn-xdr container if it exists..."
    if docker rm -f hardn-xdr 2>/dev/null; then
        log_info "Removed existing hardn-xdr container"
    else
        log_info "No existing hardn-xdr container to remove"
    fi

    # Build with BuildKit enabled
    log_info "Building Docker image hardn-xdr:deb13 with BuildKit..."
    if DOCKER_BUILDKIT=1 docker build -t hardn-xdr:deb13 .; then
        log_info "Docker image built successfully ✓"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi

    # Run
    log_info "Running hardn-xdr container..."
    if docker run --name hardn-xdr -d hardn-xdr:deb13; then
        log_info "Container hardn-xdr started successfully ✓"
    else
        log_error "Failed to start hardn-xdr container"
        exit 1
    fi
}

tmp_pull(){
    log_info "Starting tmp_pull function..."

    # read only + tmpfs
    log_info "Removing existing hardn-xdr container if it exists..."
    if docker rm -f hardn-xdr 2>/dev/null; then
        log_info "Removed existing hardn-xdr container"
    else
        log_info "No existing hardn-xdr container to remove"
    fi

    log_info "Running hardn-xdr with security enhancements (read-only + tmpfs)..."
    if docker run --name hardn-xdr -d \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,mode=1777,size=64m \
      --tmpfs /run:rw,noexec,nosuid,mode=0755,size=16m \
      --tmpfs /home/hardn:rw,mode=0755,size=32m \
      --tmpfs /opt/hardn-xdr:rw,mode=0755,size=64m \
      hardn-xdr:deb13; then
        log_info "Hardened container started successfully ✓"
    else
        log_error "Failed to start hardened container"
        exit 1
    fi

    # Pull and run published image from GHCR (fixed lowercase)
    log_info "Pulling published image from GHCR..."
    if docker pull ghcr.io/opensource-for-freedom/hardn_debian_docker_image:deb13; then
        log_info "Image pulled successfully ✓"
    else
        log_error "Failed to pull image from GHCR"
        exit 1
    fi

    log_info "Running published image..."
    if docker run --name hardn-xdr-ghcr -d ghcr.io/opensource-for-freedom/hardn_debian_docker_image:deb13; then
        log_info "GHCR container started successfully ✓"
    else
        log_error "Failed to start GHCR container"
        exit 1
    fi
}

# Main execution
main() {
    log_info "Starting Docker deployment script..."

    # Perform all checks
    check_sudo
    check_docker
    check_dockerfile

    # Execute functions
    prep_build
    tmp_pull

    log_info "All operations completed successfully! ✓"
    log_info "Active containers:"
    docker ps --filter "name=hardn-xdr"
}

# Run main function
main "$@"
