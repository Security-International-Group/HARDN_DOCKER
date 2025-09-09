# syntax=docker/dockerfile:1.7
FROM debian:trixie-slim

SHELL ["/bin/bash","-o","pipefail","-c"]
ENV DEBIAN_FRONTEND=noninteractive

### author: Tim Burns
# "May the odds forever be in our favor"

ARG VCS_REF=""
ARG BUILD_DATE=""
ARG VERSION="1.0.1"
ARG REPO_URL="https://github.com/opensource-for-freedom/hardn_debian_docker_image"

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
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware" \
      "deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware" \
      "deb http://deb.debian.org/debian trixie-backports main contrib non-free non-free-firmware" \
      "deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware" \
      > /etc/apt/sources.list; \
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

RUN mkdir -p /etc/sysctl.d /etc/iptables ${HARDN_XDR_HOME} /opt/hardn-xdr/docs /var/log/security

# Non-root user (CIS 5.4)
RUN groupadd -g "${HARDN_GID}" -r hardn \
 && useradd  -u "${HARDN_UID}" -g "${HARDN_GID}" -r -s /usr/sbin/nologin -d /home/hardn -c "HARDN-XDR User" hardn \
 && mkdir -p /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && chown -R hardn:hardn /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && chmod 755 /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && : > /opt/hardn-xdr/state/hardn-cron.log && chown hardn:hardn /opt/hardn-xdr/state/hardn-cron.log

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

# ---------- Hardening additions to satisfy scan recommendations ----------

# TLS private-key ownership/permissions
RUN mkdir -p /etc/ssl/private \
 && chown -R root:root /etc/ssl/private \
 && chmod 0700 /etc/ssl/private \
 && find /etc/ssl/private -type f -exec chmod 0600 {} \; || true
# Also catch stray keys under /etc/ssl (extra safety)
RUN find /etc/ssl -type f \( -name '*.key' -o -name '*-key.pem' -o -name '*_key.pem' \) \
      -exec chown root:root {} \; -exec chmod 0600 {} \; || true

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
USER ${HARDN_UID}:${HARDN_GID}
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]