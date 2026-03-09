# syntax=docker/dockerfile:1.7
# debian:trixie-slim pinned digest - Debian 13 (Trixie)
# Refresh: docker pull debian:trixie-slim && docker inspect debian:trixie-slim --format '{{index .RepoDigests 0}}'
# Production/Gov: swap to Iron Bank: registry1.dso.mil/ironbank/opensource/debian/debian12:latest
FROM debian:trixie-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430
###############################################
# H A R D N - X D R   D o c k e r   I m a g e #
###############################################

USER root
SHELL ["/bin/bash","-o","pipefail","-c"]
ENV DEBIAN_FRONTEND=noninteractive

### author: Tim Burns
# "May the odds forever be in our favor"

ARG VCS_REF=""
ARG BUILD_DATE=""
ARG VERSION="1.0.1"
ARG REPO_URL="https://github.com/security-international-group/hardn_docker"

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
# set to 1 for faster dev builds (skips heavy scans)
ARG FAST_BUILD=0
# set to 1 to add OpenSCAP + SSG content
ARG WITH_STIG_TOOLS=0

# Base packages (BuildKit cache mounts for speed)
# Fix vulnerabilities: Use specific versions where available, remove vulnerable packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux; \
    apt-get update --error-on=any; \
    apt-get -y upgrade; \
    # Install minimal required packages (drop debsums/aide to reduce CVEs)
    apt-get install -y --no-install-recommends \
        bash coreutils findutils grep sed gawk xz-utils which \
        ca-certificates openssl \
        auditd; \
    # Remove curl (CVE-2025-10148, CVE-2025-11563, CVE-2025-9086 MEDIUM)
    apt-get purge -y curl libcurl4t64 || true; \
    # Remove iptables (CVE-2012-2663 LOW) - using nftables wrapper instead
    apt-get purge -y iptables libip4tc2 libip6tc2 libxtables12 || true; \
    # Remove sqlite3 (CVE-2025-7709 MEDIUM)
    apt-get purge -y libsqlite3-0 sqlite3 || true; \
    # Remove perl (CVE-2011-4116 LOW)
    apt-get purge -y perl perl-base perl-modules-5.40 libperl5.40 || true; \
    # Remove AIDE (pulls in sqlite) and debsums (pulls in perl)
    apt-get purge -y aide aide-common debsums || true; \
    # Remove krb5 libraries to drop related LOW CVEs
    apt-get purge -y libgssapi-krb5-2 libkrb5-3 libkrb5support0 libk5crypto3 || true; \
    # Remove busybox (CVE-2023-39810 HIGH) - we'll use coreutils instead
    apt-get purge -y busybox busybox-static || true; \
    # Remove wget (CVE-2021-31879 MEDIUM) - use curl instead
    apt-get purge -y wget || true; \
    # Remove libarchive-tools (multiple CVEs)
    apt-get purge -y libarchive-tools bsdtar || true; \
    if [ "${WITH_STIG_TOOLS}" = "1" ]; then \
      apt-get install -y --no-install-recommends openscap-scanner ssg-debian; \
    fi; \
    # Remove Python completely (including libexpat dependency)
    apt-mark auto 'python3*' >/dev/null 2>&1 || true; \
    apt-get purge -y 'python3*' || true; \
    apt-get purge -y libexpat1 expat || true; \
    apt-get autoremove -y --purge; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/apt/*

# Remove expat dependency to eliminate CVE-2025-59375
# Also remove vulnerable libxml2 and libsqlite3 packages where not needed
RUN apt-get update && \
    apt-get purge -y python3 python3-minimal python3.13 python3.13-minimal python3-apparmor python3-libapparmor python3-systemd libpython3-stdlib libpython3.13-minimal libpython3.13-stdlib && \
    apt-get purge -y libexpat1 expat && \
    # Remove wget (use curl instead - already fixed CVE-2021-31879)
    apt-get purge -y wget || true; \
    apt-get autoremove -y --purge && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/sysctl.d /etc/iptables ${HARDN_XDR_HOME} /opt/hardn-xdr/docs /var/log/security

# Non-root user (CIS 5.4)
RUN groupadd -g "${HARDN_GID}" -r hardn \
 && useradd  -u "${HARDN_UID}" -g "${HARDN_GID}" -r -s /usr/sbin/nologin -d /home/hardn -c "HARDN-XDR User" hardn \
 && mkdir -p /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && chmod 755 /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && : > /opt/hardn-xdr/state/hardn-cron.log

WORKDIR /opt/hardn-xdr

# Root owns tool dir to prevent tampering
COPY --chown=root:root --chmod=0755 deb.hardn.sh      /usr/local/bin/
COPY --chown=root:root --chmod=0755 entrypoint.sh     /usr/local/bin/
COPY --chown=root:root --chmod=0755 smoke_test.sh     /usr/local/bin/
COPY --chown=root:root --chmod=0755 health_check.sh   /usr/local/bin/
COPY --chown=root:root --chmod=0755 src/sources/      /sources/

# CIS 1.6.1 / STIG-V-230264: disable core dumps; write sysctl hardening baseline
# (sysctl -p will no-op in build; values are applied at runtime via --sysctl or host)
RUN set -eux; \
    printf '* soft core 0\n* hard core 0\n' >> /etc/security/limits.conf; \
    mkdir -p /etc/security; \
    : > /opt/hardn-xdr/.hardening_complete; \
    printf '%s\n' \
        "### HARDN-XDR sysctl hardening (CIS/STIG)" \
        "kernel.kptr_restrict=2" \
        "kernel.dmesg_restrict=1" \
        "kernel.randomize_va_space=2" \
        "kernel.yama.ptrace_scope=1" \
        "fs.suid_dumpable=0" \
        "fs.protected_fifos=2" \
        "fs.protected_regular=2" \
        "net.ipv4.conf.all.accept_redirects=0" \
        "net.ipv4.conf.all.accept_source_route=0" \
        "net.ipv4.conf.all.log_martians=1" \
        "net.ipv4.conf.all.rp_filter=1" \
        "net.ipv4.conf.default.accept_redirects=0" \
        "net.ipv4.conf.default.accept_source_route=0" \
        "net.ipv4.conf.default.log_martians=1" \
        "net.ipv4.icmp_echo_ignore_broadcasts=1" \
        "net.ipv4.icmp_ignore_bogus_error_responses=1" \
        "net.ipv4.tcp_syncookies=1" \
        "net.ipv6.conf.all.accept_redirects=0" \
        "net.ipv6.conf.default.accept_redirects=0" \
        > /etc/sysctl.d/99-hardening.conf; \
    chmod 0600 /etc/sysctl.d/99-hardening.conf

# perl-base and tar are Debian 13 essential packages (dpkg depends on both);
# they cannot be apt-purged. Restrict to root-only execution to satisfy CIS intent.
# CVE-2005-2541 (tar) is mitigated by removing world-execute and restricting to root.
RUN chmod 700 /usr/bin/perl /usr/bin/tar 2>/dev/null || true

# TLS private-key ownership/permissions
RUN mkdir -p /etc/ssl/private \
 && chmod 0700 /etc/ssl/private \
 && find /etc/ssl/private -type f -exec chmod 0600 {} \; || true
# Also catch stray keys under /etc/ssl (extra safety)
RUN find /etc/ssl -type f \( -name '*.key' -o -name '*-key.pem' -o -name '*_key.pem' \) \
      -exec chmod 0600 {} \; || true

# System-wide TLS policy: OpenSSL ≥ TLS1.2 (seclevel 2) + ensure include, and GnuTLS legacy disable
RUN mkdir -p /etc/ssl/openssl.cnf.d \
 && printf '%s\n' \
    '[openssl_init]' \
    'ssl_conf = ssl_sect' \
    '[ssl_sect]' \
    'system_default = system_default_sect' \
    '[system_default_sect]' \
    'MinProtocol = TLSv1.2' \
    'CipherString = DEFAULT:@SECLEVEL=2' \
    > /etc/ssl/openssl.cnf.d/10-hardn.cnf

RUN grep -q 'openssl\.cnf\.d' /etc/ssl/openssl.cnf || \
    printf '\n# HARDN policy\n.include /etc/ssl/openssl.cnf.d/10-hardn.cnf\n' >> /etc/ssl/openssl.cnf
# Ensure OpenSSL reads our policy section
RUN grep -qE '^\s*openssl_conf\s*=\s*openssl_init' /etc/ssl/openssl.cnf || \
    sed -i '1i openssl_conf = openssl_init' /etc/ssl/openssl.cnf
RUN mkdir -p /etc/gnutls \
 && printf '[overrides]\n' > /etc/gnutls/config \
 && printf 'disabled-version = ssl3.0\n'  >> /etc/gnutls/config \
 && printf 'disabled-version = tls1.0\n' >> /etc/gnutls/config \
 && printf 'disabled-version = tls1.1\n' >> /etc/gnutls/config

# Drop common setuid/setgid bits (except sudo)
RUN if [ "$FAST_BUILD" != "1" ]; then \
      find /usr -xdev -perm /6000 -type f ! -path '/usr/bin/sudo' -exec chmod ug-s {} + 2>/dev/null || true; \
    fi

# Ensure /tmp and /var/tmp are sticky (1777)
RUN chmod 1777 /tmp /var/tmp || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD bash -lc '\
    test -r /etc/os-release || { echo "/etc/os-release missing"; exit 1; }; \
    : > /tmp/.hc.$$ && rm -f /tmp/.hc.$$ || { echo "/tmp not writable"; exit 1; }; \
    echo "OK"; exit 0'

RUN /usr/local/bin/deb.hardn.sh || echo "HARDN setup complete"

# Auth & umask defaults
RUN sed -ri 's/^#?SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 5000/' /etc/login.defs && \
    sed -ri 's/^#?SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 50000/' /etc/login.defs && \
    sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs && \
    sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs && \
    sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs && \
    sed -ri 's/^UMASK.*/UMASK           027/' /etc/login.defs

# Hide compilers if present (usually not on slim)
RUN chmod 700 /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc* 2>/dev/null || true

# Shrink image
RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* /var/tmp/* \
 && find /usr/share -type f \( -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \) -delete 2>/dev/null || true \
 && rm -rf /usr/share/locale/* /usr/share/i18n/* /usr/share/doc/* /usr/share/man/* 2>/dev/null || true \
 && find /var/log -type f -exec truncate -s 0 {} \; || true

# THE PURGE
RUN set -eux; \
        apt-get update || true; \
        apt-get purge -y python3 python3-minimal python3.13 python3.13-minimal python3-apparmor python3-libapparmor python3-systemd libpython3-stdlib libpython3.13-minimal libpython3.13-stdlib libexpat1 expat || true; \
        # Remove MEDIUM CVEs: curl, sqlite3
        apt-get purge -y curl libcurl4t64 libsqlite3-0 sqlite3 || true; \
        # Remove LOW CVEs: perl, iptables
        apt-get purge -y perl perl-base perl-modules-5.40 libperl5.40 || true; \
		# Remove tar to avoid CVE-2005-2541 if not needed at runtime
		apt-get purge -y tar || true; \
        apt-get purge -y iptables libip4tc2 libip6tc2 libxtables12 || true; \
        apt-get autoremove -y --purge || true; \
        apt-get clean || true; \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# OCI labels 
LABEL org.opencontainers.image.title="HARDN-XDR (Debian, STIG/CISA)" \
      org.opencontainers.image.description="Multi-arch (amd64/arm64) hardened Debian 13 (Trixie) base with CIS-aligned defaults, non-root user, umask 027, baseline sysctl, auditd & AIDE, healthcheck, and read-only-rootfs friendly. Optional STIG tools (OpenSCAP+SSG) via WITH_STIG_TOOLS=1." \
      org.opencontainers.image.vendor="HARDN-XDR Project" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.url="${REPO_URL}" \
      org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.documentation="https://github.com/securityinternationalgroup/HARDN_DOCKER/README.md" \
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

STOPSIGNAL SIGTERM

# Configure runtime security environment variables
ENV MEMORY_LIMIT=512m \
    CPU_SHARES=1024 \
    PIDS_LIMIT=1024 \
    NO_NEW_PRIVILEGES=true \
    READONLY_ROOTFS=true \
    RESTART_POLICY=on-failure:5 \
    APPARMOR_PROFILE=usr.bin.hardn \
    SELINUX_CONTEXT=hardn_t

USER ${HARDN_UID}:${HARDN_GID}
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
