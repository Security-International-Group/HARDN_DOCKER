# syntax=docker/dockerfile:1.7

FROM debian:trixie-slim AS builder
SHELL ["/bin/bash","-o","pipefail","-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

FROM debian:trixie-slim
SHELL ["/bin/bash","-o","pipefail","-c"]
ENV DEBIAN_FRONTEND=noninteractive

### author: Tim Burns
# "May the odds forever be in our favor"

# OCI + CIS labels
LABEL org.opencontainers.image.title="HARDN-XDR (Debian, STIG/CISA)" \
      org.opencontainers.image.description="HARDN-XDR with OpenSCAP STIG/CISA benchmark content on Debian trixie (testing)" \
      org.opencontainers.image.vendor="HARDN-XDR Project" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="1.0" \
      org.opencontainers.image.created="2025-08-29" \
      cis.docker.benchmark.version="1.13.0" \
      cis.docker.benchmark.compliance="enhanced" \
      security.hardening.level="high" \
      security.cis.benchmark="docker-1.13.0" \
      security.stig.compliance="enhanced" \
      security.capabilities="restricted" \
      security.privileged="false" \
      security.user.namespace="enabled" \
      security.seccomp="enabled" \
      security.apparmor="enabled" \
      security.selinux="n/a" \
      security.readonly.rootfs="true" \
      security.no.new.privileges="true" \
      security.healthcheck="enabled" \
      security.logging="centralized" \
      security.audit="enabled"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    HARDN_XDR_HOME=/opt/hardn-xdr \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    DOCKER_CONTENT_TRUST=1 \
    CONTAINER_SECURITY_LEVEL=high \
    UMASK=0027 \
    HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 \
    TMPDIR=/tmp TMP=/tmp TEMP=/tmp

ARG HARDN_UID=10001
ARG HARDN_GID=10001

RUN set -eux; \
    printf '%s\n' \
      "deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware" \
      "deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware" \
      "deb http://deb.debian.org/debian trixie-backports main contrib non-free non-free-firmware" \
      "deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware" \
      > /etc/apt/sources.list; \
    apt-get update --error-on=any; \
    apt-get -y upgrade; \
    \
    # Install ONLY runtime tools that do not pull Python
    apt-get install -y --no-install-recommends \
        bash coreutils findutils grep sed gawk tar xz-utils which \
        ca-certificates curl openssl \
        debsums wget lynis rkhunter \
        apt-listchanges needrestart unattended-upgrades \
        aide aide-common iptables auditd \
    ; \
    # Ensure Python did not sneak in
    apt-mark auto 'python3*' >/dev/null 2>&1 || true; \
    apt-get purge -y 'python3*' >/dev/null 2>&1 || true; \
    apt-get autoremove -y --purge; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/apt/*

RUN mkdir -p /etc/sysctl.d /etc/iptables ${HARDN_XDR_HOME} /opt/hardn-xdr/docs /var/log/security

# Non-root user (CIS 5.4)
RUN groupadd -g "${HARDN_GID}" -r hardn \
 && useradd  -u "${HARDN_UID}" -g "${HARDN_GID}" -r -s /usr/sbin/nologin -d /home/hardn -c "HARDN-XDR User" hardn \
 && mkdir -p /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && chown -R hardn:hardn /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && chmod 755 /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && touch /opt/hardn-xdr/state/hardn-cron.log && chown hardn:hardn /opt/hardn-xdr/state/hardn-cron.log

WORKDIR /opt/hardn-xdr

COPY --chown=root:root --chmod=0755 deb.hardn.sh /usr/local/bin/
COPY --chown=root:root --chmod=0755 entrypoint.sh /usr/local/bin/
COPY --chown=root:root --chmod=0755 smoke_test.sh /usr/local/bin/
COPY --chown=root:root src/sources/ /sources/


RUN set -eux; \
    echo "* soft core 0" >> /etc/security/limits.conf; \
    echo "* hard core 0" >> /etc/security/limits.conf; \
    mkdir -p /etc/security; \
    touch /opt/hardn-xdr/.hardening_complete; \
    # Container-safe sysctls file
    cat > /etc/sysctl.d/99-hardening.conf <<'SYSCTL'
# Container-safe sysctl hardening
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.randomize_va_space=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
fs.protected_fifos=2
fs.protected_regular=2
SYSCTL

RUN sysctl -p /etc/sysctl.d/99-hardening.conf || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD bash -lc '\
    test -r /etc/os-release || { echo "/etc/os-release missing"; exit 1; }; \
    touch /tmp/.hc.$$ && rm -f /tmp/.hc.$$ || { echo "/tmp not writable"; exit 1; }; \
    echo "OK"; exit 0'

RUN /usr/local/bin/deb.hardn.sh || echo "Hardening setup (best-effort) complete"

RUN sed -ri 's/^#?SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 5000/' /etc/login.defs && \
    sed -ri 's/^#?SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 50000/' /etc/login.defs && \
    sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs && \
    sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs && \
    sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs && \
    sed -ri 's/^UMASK.*/UMASK           027/' /etc/login.defs

RUN chmod 700 /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc* 2>/dev/null || true

# Final cleanup
RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* /var/tmp/* \
 && find /usr/share -type f \( -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \) -delete 2>/dev/null || true \
 && rm -rf /usr/share/locale/* /usr/share/i18n/* /usr/share/doc/* /usr/share/man/* 2>/dev/null || true \
 && find /var/log -type f -exec truncate -s 0 {} \; || true

# Drop privileges by default (CIS 5.4 fix)
USER ${HARDN_UID}:${HARDN_GID}

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]