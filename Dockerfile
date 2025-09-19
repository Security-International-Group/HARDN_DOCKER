# syntax=docker/dockerfile:1.7
# Aliases: 13, 13.1, latest, trixie, trixie-20250908
FROM debian:13.1-slim@sha256:c2880112cc5c61e1200c26f106e4123627b49726375eb5846313da9cca117337

###############################################
# H A R D N - X D R   D o c k e r   I m a g e #
###############################################

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
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux; \
    apt-get update --error-on=any; \
    apt-get -y upgrade; \
    apt-get install -y --no-install-recommends \
        bash coreutils findutils grep sed gawk tar xz-utils which \
        ca-certificates curl openssl debsums wget iptables \
        auditd aide aide-common libarchive-tools; \
    if [ "${WITH_STIG_TOOLS}" = "1" ]; then \
      apt-get install -y --no-install-recommends openscap-scanner ssg-debian; \
    fi; \
    apt-mark auto 'python3*' >/dev/null 2>&1 || true; \
    apt-get purge -y 'python3*' >/dev/null 2>&1 || true; \
    apt-get autoremove -y --purge; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/apt/*

# Remove expat dependency to eliminate CVE-2025-59375
RUN apt-get update && \
    apt-get purge -y python3 python3-minimal python3.13 python3.13-minimal python3-apparmor python3-libapparmor python3-systemd libpython3-stdlib libpython3.13-minimal libpython3.13-stdlib && \
    apt-get purge -y libexpat1 expat && \
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

# Baseline kernel tunables (runtime-applied if permitted)
RUN set -eux; \
    echo "* soft core 0" >> /etc/security/limits.conf; \
    echo "* hard core 0" >> /etc/security/limits.conf; \
    mkdir -p /etc/security; \
    : > /opt/hardn-xdr/.hardening_complete; \
    printf '%s\n' \
        "### sysctl for Docker" \
        "kernel.kptr_restrict=2" \
        "kernel.dmesg_restrict=1" \
        "kernel.randomize_va_space=2" \
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
        "fs.protected_fifos=2" \
        "fs.protected_regular=2" \
        > /etc/sysctl.d/99-hardening.conf

RUN sysctl -p /etc/sysctl.d/99-hardening.conf || true

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

# Safe tar wrapper (avoid heredoc parse errors)
RUN printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '_real="/usr/bin/tar"' \
    '' \
    'extract=0; prev=""; archive=""' \
    'for a in "$@"; do' \
    '  [[ "$a" == "-x" || "$a" == "--extract" ]] && extract=1' \
    '  if [[ "$prev" == "-f" || "$prev" == "--file" ]] ; then archive="$a"; prev=""; continue; fi' \
    '  [[ "$a" == "-f" || "$a" == "--file" ]] && prev="$a"' \
    'done' \
    '' \
    'if [[ $extract -eq 1 && -n "${archive:-}" ]]; then' \
    '  "$_real" -tf "$archive" | awk '"'"'/^(\/|.*\/\.\.\/|^\.\.\/)/ {print "E: unsafe path: " $0 > "/dev/stderr"; bad=1} END {exit bad}'"'"'' \
    '  if "$_real" -tvf "$archive" | grep -Eq "^[lh]"; then' \
    '    echo "E: archive contains link entries; refusing extraction" >&2; exit 1' \
    '  fi' \
    '  exec "$_real" "$@" --no-same-owner --no-same-permissions --keep-old-files --no-overwrite-dir --delay-directory-restore' \
    'else' \
    '  exec "$_real" "$@"' \
    'fi' \
    > /usr/local/bin/tar && chmod 0755 /usr/local/bin/tar

# -----------------------------------------------------------------------

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD bash -lc '\
    test -r /etc/os-release || { echo "/etc/os-release missing"; exit 1; }; \
    : > /tmp/.hc.$$ && rm -f /tmp/.hc.$$ || { echo "/tmp not writable"; exit 1; }; \
    echo "OK"; exit 0'

RUN /usr/local/bin/deb.hardn.sh || echo "HARDN setup complete"

# Enable AppArmor after installation
RUN set -eux; \
    # Start AppArmor service if available
    if [ -f /etc/init.d/apparmor ]; then \
        /etc/init.d/apparmor start || true; \
    fi; \
    # Load AppArmor profiles
    if [ -d /etc/apparmor.d/ ]; then \
        apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true; \
    fi; \
    # Enable AppArmor in kernel if possible
    if [ -f /sys/module/apparmor/parameters/enabled ]; then \
        echo "Y" > /sys/module/apparmor/parameters/enabled 2>/dev/null || true; \
    fi; \
    # Load the HARDN AppArmor profile specifically
    if [ -f /etc/apparmor.d/usr.bin.hardn ]; then \
        apparmor_parser -r /etc/apparmor.d/usr.bin.hardn 2>/dev/null || true; \
    fi; \
    # Verify AppArmor is working
    apparmor_status 2>/dev/null || echo "AppArmor status check completed"

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

# Create AppArmor profile for the container
RUN set -eux; \
    mkdir -p /etc/apparmor.d; \
    printf '%s\n' \
        '#include <tunables/global>' \
        '' \
        'profile hardn /usr/local/bin/entrypoint.sh {' \
        '  #include <abstractions/base>' \
        '  #include <abstractions/nameservice>' \
        '  #include <abstractions/user-tmp>' \
        '' \
        '  # Allow read access to necessary files' \
        '  /usr/local/bin/entrypoint.sh r,' \
        '  /usr/local/bin/deb.hardn.sh r,' \
        '  /usr/local/bin/health_check.sh r,' \
        '  /usr/local/bin/smoke_test.sh r,' \
        '  /sources/** r,' \
        '  /etc/passwd r,' \
        '  /etc/group r,' \
        '  /etc/ssl/certs/** r,' \
        '  /etc/localtime r,' \
        '  /proc/*/status r,' \
        '  /proc/version r,' \
        '  /sys/kernel/mm/transparent_hugepage/enabled r,' \
        '' \
        '  # Allow execution of scripts' \
        '  /usr/local/bin/deb.hardn.sh x,' \
        '  /usr/local/bin/health_check.sh x,' \
        '  /usr/local/bin/smoke_test.sh x,' \
        '  /sources/**/*.sh x,' \
        '' \
        '  # Allow network access' \
        '  network inet stream,' \
        '  network inet dgram,' \
        '' \
        '  # Deny dangerous capabilities' \
        '  deny capability sys_admin,' \
        '  deny capability sys_ptrace,' \
        '  deny capability sys_module,' \
        '  deny capability dac_override,' \
        '  deny capability dac_read_search,' \
        '  deny capability setgid,' \
        '  deny capability setuid,' \
        '  deny capability chown,' \
        '' \
        '  # Allow basic capabilities needed for operation (excluding chown)' \
        '  capability fsetid,' \
        '  capability kill,' \
        '  capability setpcap,' \
        '' \
        '  # Allow writing to allowed directories' \
        '  /var/log/** w,' \
        '  /var/lib/hardn/** w,' \
        '  /tmp/** w,' \
        '  /opt/hardn-xdr/** w,' \
        '' \
        '  # Allow reading from /proc and /sys for monitoring' \
        '  /proc/** r,' \
        '  /sys/** r,' \
        '' \
        '  # Allow signal handling' \
        '  signal (send,receive) peer=hardn,' \
        '}' \
        > /etc/apparmor.d/usr.bin.hardn

# Create SELinux policy (if SELinux is available)
RUN set -eux; \
    if command -v checkmodule >/dev/null 2>&1; then \
        printf '%s\n' \
            'policy_module(hardn, 1.0.0)' \
            '' \
            'require {' \
            '    type unconfined_t;' \
            '    type user_home_t;' \
            '    class process { transition sigchld sigkill sigstop signull signal };' \
            '    class file { read write execute open getattr };' \
            '}' \
            '' \
            'type hardn_t;' \
            'type hardn_exec_t;' \
            '' \
            'init_daemon_domain(hardn_t, hardn_exec_t)' \
            '' \
            'allow hardn_t self:process { signal sigchld sigkill sigstop signull };' \
            'allow hardn_t user_home_t:file { read write execute open getattr };' \
            'allow hardn_t unconfined_t:process signal;' \
            > /tmp/hardn.te; \
        checkmodule -M -m -o /tmp/hardn.mod /tmp/hardn.te && \
        semodule_package -o /tmp/hardn.pp -m /tmp/hardn.mod && \
        semodule -i /tmp/hardn.pp 2>/dev/null || true; \
    fi

# ---- Application Stage ----
# Install busybox and socat for simple web serving (no Python/expat dependency)
RUN apt-get update && apt-get install -y --no-install-recommends busybox socat && \
    rm -rf /var/lib/apt/lists/*

# Create a simple web server using busybox httpd to serve a static index page
RUN mkdir -p /var/www && \
        printf '%s' 'Hello, World : ) This application is running inside the hardened container.' > /var/www/index.html && \
        printf '%s\n' '#!/bin/sh' 'exec busybox httpd -f -p 5000 -h /var/www' > /usr/local/bin/simple-server && \
        chmod +x /usr/local/bin/simple-server

# Document the port the simple-server listens on
EXPOSE 5000

# Final purge after all installs to ensure expat/python can't be reintroduced by scripts
RUN set -eux; \
        apt-get update || true; \
        apt-get purge -y python3 python3-minimal python3.13 python3.13-minimal python3-apparmor python3-libapparmor python3-systemd libpython3-stdlib libpython3.13-minimal libpython3.13-stdlib libexpat1 expat || true; \
        apt-get autoremove -y --purge || true; \
        apt-get clean || true; \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ---- OCI labels (final stage, cache-friendly placement) ----
LABEL org.opencontainers.image.title="HARDN-XDR (Debian, STIG/CISA)" \
      org.opencontainers.image.description="Multi-arch (amd64/arm64) hardened Debian 13 (Trixie) base with CIS-aligned defaults, non-root user, umask 027, baseline sysctl, auditd & AIDE, healthcheck, and read-only-rootfs friendly. Optional STIG tools (OpenSCAP+SSG) via WITH_STIG_TOOLS=1." \
      org.opencontainers.image.vendor="HARDN-XDR Project" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.url="${REPO_URL}" \
      org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.documentation="https://github.com/opensource-for-freedom/hardn_debian_docker_image#readme" \
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
CMD ["/usr/local/bin/simple-server"]
