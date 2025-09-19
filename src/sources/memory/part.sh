#!/bin/bash
# HARDN-XDR Docker Partition Management
# Memory and storage security for Docker components

# Function to check Docker data partition
check_docker_partition() {
    echo "Checking Docker data partition..."

    # Check if /var/lib/docker exists
    if [ ! -d /var/lib/docker ]; then
        echo "Docker data directory /var/lib/docker does not exist yet"
        return 0
    fi

    # Get filesystem info for /var/lib/docker
    docker_fs=$(df -T /var/lib/docker 2>/dev/null | tail -1 | awk '{print $2}')
    root_fs=$(df -T / 2>/dev/null | tail -1 | awk '{print $2}')

    # Check if Docker data is on separate filesystem
    if [ "$docker_fs" != "$root_fs" ]; then
        echo "✓ Docker data is on separate partition (filesystem: $docker_fs)"
    else
        echo "⚠ WARN: Docker data (/var/lib/docker) is on the same partition as root filesystem"
        echo "   Recommendation: Create a separate partition for /var/lib/docker"
        echo "   This improves security by isolating Docker data from the root filesystem"
        echo ""
        echo "   On Linux systems, you can:"
        echo "   1. Create a new partition/LVM volume"
        echo "   2. Format and mount it at /var/lib/docker"
        echo "   3. Update /etc/fstab accordingly"
        echo ""
        echo "   On Windows with Docker Desktop:"
        echo "   - Docker Desktop uses WSL2 or Hyper-V which handles storage differently"
        echo "   - Consider using Docker Desktop's advanced settings for disk management"
        echo "   - Monitor disk usage in Docker Desktop settings"
    fi
}

# Function to create separate Docker partition (Linux only)
create_docker_partition() {
    echo "Creating separate Docker partition..."

    # This is a helper function - actual partition creation requires manual steps
    echo "NOTE: This function provides guidance for creating a separate Docker partition"
    echo "      Actual partition creation requires system administrator intervention"
    echo ""

    # Check available disk space
    echo "Available disk space:"
    df -h | grep -E "^/dev/"

    echo ""
    echo "Steps to create separate Docker partition:"
    echo "1. Identify available disk or create new partition using tools like fdisk, parted, or LVM"
    echo "2. Format the new partition (recommended: ext4 or xfs)"
    echo "3. Create mount point: mkdir -p /var/lib/docker"
    echo "4. Mount the partition: mount /dev/NEW_PARTITION /var/lib/docker"
    echo "5. Update /etc/fstab to mount automatically on boot"
    echo "6. Copy existing Docker data: rsync -av /var/lib/docker.bak/ /var/lib/docker/"
    echo "7. Restart Docker daemon"
    echo ""

    # Create backup if Docker data exists
    if [ -d /var/lib/docker ] && [ "$(ls -A /var/lib/docker)" ]; then
        echo "Backing up existing Docker data..."
        mkdir -p /var/lib/docker.bak
        cp -r /var/lib/docker/* /var/lib/docker.bak/ 2>/dev/null || true
        echo "Backup created at /var/lib/docker.bak"
    fi

    echo "Please follow the steps above manually to create the separate partition"
}

# Function to check memory limits for containers
check_memory_limits() {
    echo "Checking memory limits for Docker containers..."

    # Check if Docker daemon has memory limits configured
    if grep -q "memory" /etc/docker/daemon.json 2>/dev/null; then
        echo "✓ Memory limits configured in daemon.json"
    else
        echo "⚠ INFO: No memory limits configured in daemon.json"
        echo "   Recommendation: Add memory limits to prevent resource exhaustion"
    fi

    # Check running containers for memory limits
    running_containers=$(docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | wc -l)
    if [ "$running_containers" -gt 1 ]; then
        echo "Running containers found. Check individual container memory limits with:"
        echo "docker inspect <container_name> | grep -A 5 Memory"
    fi
}

# Function to configure memory protection
configure_memory_protection() {
    echo "Configuring memory protection..."

    # Enable memory protection in sysctl
    echo "vm.overcommit_memory = 1" >> /etc/sysctl.conf
    echo "vm.panic_on_oom = 1" >> /etc/sysctl.conf

    # Apply settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || echo "Warning: Some memory protection settings could not be applied"

    echo "Memory protection configured"
}

# Functions are available when sourced
# export -f check_docker_partition
# export -f create_docker_partition
# export -f check_memory_limits
# export -f configure_memory_protection

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Docker Partition & Memory Security"
    echo "==========================================="

    check_docker_partition
    check_memory_limits
    configure_memory_protection

    echo ""
    echo "Partition and memory security configuration completed."
fi
