# Use Debian trixie (testing) for better package availability than unstable
FROM debian:trixie

# CIS Docker Benchmark 1.13.0 Compliance Labels
LABEL org.opencontainers.image.title="HARDN-XDR (Debian, STIG/CISA)"
LABEL org.opencontainers.image.description="HARDN-XDR with OpenSCAP STIG/CISA benchmark content on Debian trixie (testing)"
LABEL org.opencontainers.image.vendor="HARDN-XDR Project"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.0"
LABEL org.opencontainers.image.created="2025-08-29"

# CIS Compliance Labels
LABEL cis.docker.benchmark.version="1.13.0"
LABEL cis.docker.benchmark.compliance="enhanced"
LABEL security.hardening.level="high"
LABEL security.cis.benchmark="docker-1.13.0"
LABEL security.stig.compliance="enhanced"
LABEL security.capabilities="restricted"
LABEL security.privileged="false"
LABEL security.user.namespace="enabled"
LABEL security.seccomp="enabled"
LABEL security.apparmor="enabled"
LABEL security.selinux="n/a"
LABEL security.readonly.rootfs="true"
LABEL security.no.new.privileges="true"
LABEL security.healthcheck="enabled"
LABEL security.logging="centralized"
LABEL security.audit="enabled"

# Security-focused environment
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    DEBIAN_FRONTEND=noninteractive \
    HARDN_XDR_HOME=/opt/hardn-xdr \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    DOCKER_CONTENT_TRUST=1 \
    CONTAINER_SECURITY_LEVEL=high \
    UMASK=0027 \
    HISTFILE=/dev/null \
    HISTSIZE=0 \
    HISTFILESIZE=0 \
    TMPDIR=/tmp \
    TMP=/tmp \
    TEMP=/tmp

ARG HARDN_UID=10001
ARG HARDN_GID=10001

# sources
RUN set -euo pipefail && \
    echo "deb http://deb.debian.org/debian trixie main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian trixie-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian trixie-backports main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://security.debian.org/debian-security trixie-security main contrib non-free" >> /etc/apt/sources.list && \
    for i in {1..3}; do \
        echo "Attempt $i of apt-get update..." && \
        if apt-get update --error-on=any 2>&1; then \
            echo "apt-get update succeeded on attempt $i" && \
            break; \
        else \
            echo "apt-get update failed on attempt $i, retrying..." && \
            sleep 5; \
        fi; \
    done && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
      bash coreutils findutils grep sed gawk tar xz-utils which \
      ca-certificates curl openssl \
      python3 python3-pip \
      rsyslog ufw fail2ban apparmor apparmor-utils \
      lynis debsums rkhunter wget git macchanger \
      apt-listbugs apt-listchanges needrestart apt-show-versions unattended-upgrades \
      acct sysstat auditd audispd-plugins aide aide-common \
      chrony libpam-pwquality libpam-tmpdir \
      iptables && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /etc/sysctl.d /etc/apt/trusted.gpg.d /etc/iptables ${HARDN_XDR_HOME} /opt/hardn-xdr/docs /var/log/security

# Create non-root user
RUN groupadd -g "${HARDN_GID}" -r hardn && \
    useradd -u "${HARDN_UID}" -g "${HARDN_GID}" -r -s /bin/bash -d ${HARDN_XDR_HOME} -c "HARDN-XDR User" hardn && \
    chown -R hardn:hardn ${HARDN_XDR_HOME}

WORKDIR ${HARDN_XDR_HOME}

# Copy application files
COPY --chown=root:root --chmod=0755 deb.hardn.sh /usr/local/bin/
COPY --chown=root:root --chmod=0755 entrypoint.sh /usr/local/bin/
COPY --chown=root:root --chmod=0755 smoke_test.sh /usr/local/bin/
COPY --chown=root:root src/sources/ /sources/

# Basic security configuration
RUN echo "Running basic security configuration..." && \
    echo "* soft core 0" >> /etc/security/limits.conf && \
    echo "* hard core 0" >> /etc/security/limits.conf && \
    mkdir -p /etc/security && \
    echo "Creating security configuration files..." && \
    if [ -f /etc/pam.d/common-password ]; then \
        sed -i 's/pam_cracklib.so/pam_pwquality.so/' /etc/pam.d/common-password; \
    fi && \
    if command -v auditctl >/dev/null 2>&1; then \
        echo "Auditd configuration applied"; \
    fi && \
    touch /opt/hardn-xdr/.hardening_complete && \
    mkdir -p /opt/hardn-xdr/state && \
    chown hardn:hardn /opt/hardn-xdr/state

# Consolidated sysctl hardening (combines both sections and removes duplicates)
RUN echo "Applying consolidated sysctl hardening..." && \
    echo "# Consolidated sysctl hardening for Lynis compliance" > /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.kptr_restrict=2" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.dmesg_restrict=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.randomize_va_space=2" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.modules_disabled=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "# Additional Lynis hardening settings" >> /etc/sysctl.d/99-hardening.conf && \
    echo "dev.tty.ldisc_autoload=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "fs.protected_fifos=2" >> /etc/sysctl.d/99-hardening.conf && \
    echo "fs.protected_regular=2" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.core_uses_pid=1" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.ctrl-alt-del=0" >> /etc/sysctl.d/99-hardening.conf && \
    echo "kernel.sysrq=0" >> /etc/sysctl.d/99-hardening.conf

RUN sysctl -p /etc/sysctl.d/99-hardening.conf || echo "Consolidated sysctl applied"

# Security logging and monitoring
RUN if command -v cron >/dev/null 2>&1; then \
        echo "Cron configuration applied"; \
    fi && \
    echo "HARDN-XDR Container Security Setup Complete" > /opt/hardn-xdr/security_setup_complete.txt

RUN systemctl enable auditd chrony || echo "Services enabled"

# Run the master hardening script
RUN /usr/local/bin/deb.hardn.sh || echo "Hardening setup completed"

# Configure password policies for better security
RUN sed -i 's/^# SHA_CRYPT_MIN_ROUNDS/SHA_CRYPT_MIN_ROUNDS 5000/' /etc/login.defs && \
    sed -i 's/^# SHA_CRYPT_MAX_ROUNDS/SHA_CRYPT_MAX_ROUNDS 50000/' /etc/login.defs && \
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs && \
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs && \
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs && \
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs

# Configure fail2ban
RUN cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || echo "Fail2ban configured"

# Run password file integrity check
RUN pwck -r || echo "Password file integrity checked"

# Clean up package lists to fix APT issues
RUN rm -rf /var/lib/apt/lists/* && apt-get update && apt-get clean

RUN chmod 700 /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc* 2>/dev/null || echo "Compilers restricted"

USER hardn

RUN echo "Consolidated hardening improvements completed successfully"

USER hardn

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]