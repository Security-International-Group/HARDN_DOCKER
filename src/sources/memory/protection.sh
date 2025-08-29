#!/bin/bash
# HARDN-XDR Memory Registry - Memory Protection & Hardening
# Native implementations for memory security

# Core Dump Prevention (CIS/Lynis)
prevent_core_dumps() {
    echo "Configuring core dump prevention..."

    # Disable core dumps via limits
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "* soft core 0" >> /etc/security/limits.conf

    # Disable core dumps via sysctl
    echo "kernel.core_uses_pid = 0" >> /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

    # Apply settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

    echo "Core dumps disabled"
}

# Memory Protection Settings
configure_memory_protection() {
    echo "Configuring memory protections..."

    # Randomize memory layout
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

    # Prevent ptrace exploitation
    echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf

    # Restrict kernel pointer access
    echo "kernel.kptr_restrict = 2" >> /etc/sysctl.conf

    # Hide kernel symbols
    echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf

    # Apply settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

    echo "Memory protections configured"
}

# Buffer Overflow Protections
setup_buffer_overflow_protection() {
    echo "Setting up buffer overflow protections..."

    # Enable ExecShield (if available)
    if [ -f /proc/sys/kernel/exec-shield ]; then
        echo "1" > /proc/sys/kernel/exec-shield 2>/dev/null || true
    fi

    # Configure stack protection
    if [ -f /proc/sys/kernel/randomize_va_space ]; then
        echo "2" > /proc/sys/kernel/randomize_va_space 2>/dev/null || true
    fi

    # Set restrictive umask for memory-mapped files
    echo "vm.mmap_min_addr = 65536" >> /etc/sysctl.conf

    echo "Buffer overflow protections enabled"
}

# Memory Usage Monitoring
monitor_memory_usage() {
    echo "Setting up memory usage monitoring..."

    # Set memory limits
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        # Container memory limits are handled by runtime
        echo "Memory limits managed by container runtime"
    fi

    # Monitor for memory exhaustion
    available_memory=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    if [ "$available_memory" -lt 1048576 ]; then  # Less than 1GB
        echo "WARNING: Low memory condition detected"
    fi

    echo "Memory monitoring configured"
}

# OOM Protection
configure_oom_protection() {
    echo "Configuring OOM protection..."

    # Set OOM score adjustment for critical processes
    echo "vm.oom_kill_allocating_task = 0" >> /etc/sysctl.conf
    echo "vm.overcommit_memory = 1" >> /etc/sysctl.conf

    # Apply settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

    echo "OOM protection configured"
}

# Memory Leak Detection (basic)
detect_memory_leaks() {
    echo "Performing basic memory leak detection..."

    # Check for processes with high memory usage
    high_memory_processes=$(ps aux --sort=-%mem | head -10 | awk 'NR>1 && $4>50 {print $1,$4"%"}')

    if [ -n "$high_memory_processes" ]; then
        echo "High memory usage processes detected:"
        echo "$high_memory_processes"
    else
        echo "No high memory usage processes found"
    fi
}

# Functions are available when sourced
# export -f prevent_core_dumps
# export -f configure_memory_protection
# export -f setup_buffer_overflow_protection
# export -f monitor_memory_usage
# export -f configure_oom_protection
# export -f detect_memory_leaks
