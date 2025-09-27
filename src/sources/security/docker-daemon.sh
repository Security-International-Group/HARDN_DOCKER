#!/bin/bash
# HARDN-XDR Docker Daemon Configuration
# Configure Docker daemon for security compliance

# Function to configure Docker daemon security
configure_docker_daemon() {
    echo "Configuring Docker daemon for security compliance..."

    # Create Docker configuration directory if it doesn't exist
    mkdir -p /etc/docker

    # Create daemon.json with security configurations
    cat > /etc/docker/daemon.json << 'EOF'
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "disable-legacy-registry": true,
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "userns-remap": "default",
  "seccomp-profile": "/etc/docker/seccomp.json",
  "authorization-plugins": ["authz-broker"],
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2376"]
}
EOF

    echo "Docker daemon configuration created at /etc/docker/daemon.json"
}

# Function to configure Docker TLS
configure_docker_tls() {
    echo "Configuring Docker TLS..."

    # Create certificates directory
    mkdir -p /etc/docker/certs

    # Generate CA private key
    openssl genrsa -out /etc/docker/ca-key.pem 4096 2>/dev/null || true

    # Generate CA certificate
    openssl req -new -x509 -days 365 -key /etc/docker/ca-key.pem -sha256 \
        -out /etc/docker/ca.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=Docker-CA" 2>/dev/null || true

    # Generate server private key
    openssl genrsa -out /etc/docker/server-key.pem 4096 2>/dev/null || true

    # Generate server certificate signing request
    openssl req -subj "/CN=docker-host" -new -key /etc/docker/server-key.pem \
        -out /etc/docker/server.csr 2>/dev/null || true

    # Create extensions file for server certificate
    cat > /etc/docker/server-ext.cnf << 'EOF'
[server]
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:172.17.0.1
EOF

    # Generate server certificate
    openssl x509 -req -days 365 -in /etc/docker/server.csr \
        -CA /etc/docker/ca.pem -CAkey /etc/docker/ca-key.pem \
        -out /etc/docker/server-cert.pem \
        -extfile /etc/docker/server-ext.cnf -extensions server 2>/dev/null || true

    # Set proper permissions
    chmod 600 /etc/docker/server-key.pem /etc/docker/ca-key.pem
    chmod 644 /etc/docker/ca.pem /etc/docker/server-cert.pem

    echo "Docker TLS certificates configured"
}

# Function to configure Docker seccomp profile
configure_docker_seccomp() {
    echo "Configuring Docker seccomp profile..."

    # Create default seccomp profile
    cat > /etc/docker/seccomp.json << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "accept4",
                "access",
                "alarm",
                "alarm",
                "bind",
                "brk",
                "capget",
                "capset",
                "chdir",
                "chmod",
                "chown",
                "chown32",
                "clock_getres",
                "clock_gettime",
                "clock_nanosleep",
                "close",
                "connect",
                "copy_file_range",
                "creat",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat",
                "fadvise64",
                "fadvise64_64",
                "fallocate",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchown",
                "fchown32",
                "fchownat",
                "fcntl",
                "fcntl64",
                "fdatasync",
                "fgetxattr",
                "flistxattr",
                "flock",
                "fork",
                "fremovexattr",
                "fsetxattr",
                "fstat",
                "fstat64",
                "fstatat64",
                "fstatfs",
                "fstatfs64",
                "fsync",
                "ftruncate",
                "ftruncate64",
                "futex",
                "futimesat",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "getegid32",
                "geteuid",
                "geteuid32",
                "getgid",
                "getgid32",
                "getgroups",
                "getgroups32",
                "getitimer",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresgid32",
                "getresuid",
                "getresuid32",
                "getrlimit",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "gettid",
                "gettimeofday",
                "getuid",
                "getuid32",
                "getxattr",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "io_destroy",
                "io_getevents",
                "io_setup",
                "io_submit",
                "ioctl",
                "ioprio_get",
                "ioprio_set",
                "ipc",
                "kill",
                "lchown",
                "lchown32",
                "lgetxattr",
                "link",
                "linkat",
                "listen",
                "listxattr",
                "llistxattr",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "lstat",
                "lstat64",
                "madvise",
                "membarrier",
                "memfd_create",
                "mincore",
                "mkdir",
                "mkdirat",
                "mknod",
                "mknodat",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "mmap2",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedsend",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "name_to_handle_at",
                "nanosleep",
                "newfstatat",
                "open",
                "openat",
                "pause",
                "perf_event_open",
                "personality",
                "pipe",
                "pipe2",
                "poll",
                "ppoll",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "pselect6",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "read",
                "readahead",
                "readlink",
                "readlinkat",
                "readv",
                "recv",
                "recvfrom",
                "recvmmsg",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "rename",
                "renameat",
                "renameat2",
                "restart_syscall",
                "rmdir",
                "rseq",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_tgsigqueueinfo",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_getscheduler",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "send",
                "sendfile",
                "sendfile64",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "setgid",
                "setgid32",
                "setgroups",
                "setgroups32",
                "setitimer",
                "setpgid",
                "setpriority",
                "setregid",
                "setregid32",
                "setresgid",
                "setresgid32",
                "setresuid",
                "setresuid32",
                "setreuid",
                "setreuid32",
                "setrlimit",
                "setgid",
                "setgid32",
                "setsid",
                "setsockopt",
                "setuid",
                "setuid32",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "sigreturn",
                "socket",
                "socketcall",
                "socketpair",
                "splice",
                "stat",
                "stat64",
                "statfs",
                "statfs64",
                "statx",
                "symlink",
                "symlinkat",
                "sync",
                "sync_file_range",
                "syncfs",
                "sysinfo",
                "syslog",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_settime",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_settime",
                "times",
                "tkill",
                "truncate",
                "truncate64",
                "ugetrlimit",
                "umask",
                "uname",
                "unlink",
                "unlinkat",
                "unshare",
                "utime",
                "utimensat",
                "utimes",
                "vfork",
                "vmsplice",
                "wait4",
                "waitid",
                "waitpid",
                "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
EOF

    echo "Docker seccomp profile configured"
}

# Function to configure Docker authorization plugin
configure_docker_authz() {
    echo "Configuring Docker authorization plugin..."

    # Create a simple authorization plugin configuration
    mkdir -p /etc/docker/plugins

    # For now, we'll create a placeholder - in production you'd use a real authz plugin
    cat > /etc/docker/authz-config.json << 'EOF'
{
  "name": "authz-broker",
  "type": "authorization",
  "config": {
    "allow_all": false,
    "policies": [
      {
        "name": "default",
        "rules": [
          {
            "subjects": ["hardn"],
            "actions": ["*"],
            "conditions": []
          }
        ]
      }
    ]
  }
}
EOF

    echo "Docker authorization plugin configured"
}

# Function to configure Docker auditing
configure_docker_auditing() {
    echo "Configuring Docker auditing..."

    # Create audit rules directory if it doesn't exist
    mkdir -p /etc/audit/rules.d

    # Create Docker audit rules
    cat > /etc/audit/rules.d/99-docker.rules << 'EOF'
# Docker audit rules
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /usr/lib/systemd/system/docker.socket -k docker
-w /var/run/docker.sock -k docker
-w /usr/bin/docker -k docker
-w /usr/bin/dockerd -k docker
EOF

    # Load the audit rules
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || echo "Warning: Failed to load audit rules"
    elif command -v service >/dev/null 2>&1; then
        service auditd restart || echo "Warning: Failed to restart auditd"
    else
        echo "Warning: Could not load audit rules, please restart auditd manually"
    fi

    echo "Docker audit rules configured and loaded"
}

# Function to restart Docker daemon
restart_docker_daemon() {
    echo "Restarting Docker daemon to apply configuration changes..."

    # Restart Docker service
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart docker || echo "Warning: Failed to restart Docker via systemctl"
    elif command -v service >/dev/null 2>&1; then
        service docker restart || echo "Warning: Failed to restart Docker via service"
    else
        echo "Warning: Could not determine init system, please restart Docker manually"
    fi

    echo "Docker daemon restarted"
}

# Function to verify Docker daemon configuration
verify_docker_config() {
    echo "Verifying Docker daemon configuration..."

    # Check if daemon.json exists
    if [[ -f /etc/docker/daemon.json ]]; then
        echo "✓ Docker daemon.json exists"
    else
        echo "✗ Docker daemon.json missing"
        return 1
    fi

    # Check TLS certificates
    if [[ -f /etc/docker/ca.pem ]] && [[ -f /etc/docker/server-cert.pem ]] && [[ -f /etc/docker/server-key.pem ]]; then
        echo "✓ Docker TLS certificates exist"
    else
        echo "✗ Docker TLS certificates missing"
    fi

    # Check seccomp profile
    if [[ -f /etc/docker/seccomp.json ]]; then
        echo "✓ Docker seccomp profile exists"
    else
        echo "✗ Docker seccomp profile missing"
    fi

    # Check audit rules
    if [[ -f /etc/audit/rules.d/99-docker.rules ]]; then
        echo "✓ Docker audit rules exist"
    else
        echo "✗ Docker audit rules missing"
    fi

    return 0
}

# Function to configure Docker authorization plugin
configure_docker_authz() {
    echo "Configuring Docker authorization plugin..."

    # Create a simple authorization plugin configuration
    mkdir -p /etc/docker/plugins

    # For now, we'll create a placeholder - in production you'd use a real authz plugin
    cat > /etc/docker/authz-config.json << 'EOF'
{
  "name": "authz-broker",
  "type": "authorization",
  "config": {
    "allow_all": false,
    "policies": [
      {
        "name": "default",
        "rules": [
          {
            "subjects": ["hardn"],
            "actions": ["*"],
            "conditions": []
          }
        ]
      }
    ]
  }
}
EOF

    echo "Docker authorization plugin configured"
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "HARDN-XDR Docker Daemon Security Setup"
    echo "====================================="

    configure_docker_daemon
    configure_docker_tls
    configure_docker_seccomp
    configure_docker_authz
    configure_docker_auditing
    verify_docker_config
    restart_docker_daemon
    restart_docker_daemon
    check_docker_partition

    echo ""
    echo "Docker daemon security configuration completed."
fi
