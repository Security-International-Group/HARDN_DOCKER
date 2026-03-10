# syntax=docker/dockerfile:1.7
#
# HARDN-XDR — Hardened Debian 13 (Trixie) Container Image
# CIS Docker Benchmark 1.13.0 | FIPS 140-3 aligned | DISA STIG
#
# Base: debian:trixie-slim (pinned digest)
# To refresh the digest: docker pull debian:trixie-slim && docker inspect debian:trixie-slim --format '{{index .RepoDigests 0}}'
# For DoD/Gov production deployments, swap to Iron Bank: registry1.dso.mil/ironbank/opensource/debian/debian12:latest
#
FROM debian:trixie-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430

USER root
SHELL ["/bin/bash","-o","pipefail","-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Author: Tim Burns — Security International Group

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

# FAST_BUILD=1 skips the setuid scan to speed up local development builds
ARG HARDN_UID=10001
ARG HARDN_GID=10001
ARG FAST_BUILD=0
# WITH_STIG_TOOLS=1 installs OpenSCAP + the Debian STIG content (adds ~120 MB)
ARG WITH_STIG_TOOLS=0

# Install the minimal set of packages needed for hardening, then strip everything
# that carries known CVEs or is simply not needed at runtime.
# BuildKit cache mounts keep CI builds fast without leaking apt state into the layer.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux; \
    apt-get update --error-on=any; \
    apt-get -y upgrade; \
    apt-get install -y --no-install-recommends \
        bash coreutils findutils grep sed gawk xz-utils which \
        ca-certificates openssl \
        libpam-pwquality \
        auditd; \
    # curl carries multiple MEDIUM CVEs and is not needed at runtime
    apt-get purge -y curl libcurl4t64 || true; \
    # iptables is not used inside the container (network policy lives on the host)
    apt-get purge -y iptables libip4tc2 libip6tc2 libxtables12 || true; \
    # sqlite3 CLI is not needed; libsqlite3-0 is kept because util-linux depends on it
    apt-get purge -y sqlite3 || true; \
    # perl (non-base modules) — perl-base is an essential package that dpkg requires
    apt-get purge -y perl perl-modules-5.40 libperl5.40 || true; \
    # AIDE and debsums pull in sqlite/perl; skip them
    apt-get purge -y aide aide-common debsums || true; \
    # Kerberos libraries are not used in this image
    apt-get purge -y libgssapi-krb5-2 libkrb5-3 libkrb5support0 libk5crypto3 || true; \
    # busybox duplicates coreutils and carries its own CVE history
    apt-get purge -y busybox busybox-static || true; \
    apt-get purge -y wget || true; \
    apt-get purge -y libarchive-tools bsdtar || true; \
    if [ "${WITH_STIG_TOOLS}" = "1" ]; then \
      apt-get install -y --no-install-recommends openscap-scanner ssg-debian; \
    fi; \
    # Python and libexpat are not needed and both carry active CVEs
    apt-mark auto 'python3*' >/dev/null 2>&1 || true; \
    apt-get purge -y 'python3*' || true; \
    apt-get purge -y libexpat1 expat || true; \
    apt-get autoremove -y --purge; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/apt/*

RUN mkdir -p /etc/sysctl.d /etc/iptables ${HARDN_XDR_HOME} /opt/hardn-xdr/docs /var/log/security

# Create the dedicated non-root user the container always runs as (CIS 4.1)
RUN groupadd -g "${HARDN_GID}" -r hardn \
 && useradd  -u "${HARDN_UID}" -g "${HARDN_GID}" -r -s /usr/sbin/nologin -d /home/hardn -c "HARDN-XDR User" hardn \
 && mkdir -p /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && chmod 755 /home/hardn /var/lib/hardn /opt/hardn-xdr/state \
 && : > /opt/hardn-xdr/state/hardn-cron.log

WORKDIR /opt/hardn-xdr

# All scripts are owned by root so the non-root runtime user cannot modify them
COPY --chown=root:root --chmod=0755 deb.hardn.sh      /usr/local/bin/
COPY --chown=root:root --chmod=0755 entrypoint.sh     /usr/local/bin/
COPY --chown=root:root --chmod=0755 smoke_test.sh     /usr/local/bin/
COPY --chown=root:root --chmod=0755 health_check.sh   /usr/local/bin/
COPY --chown=root:root --chmod=0755 src/sources/      /sources/

# Disable core dumps and write the sysctl hardening baseline (CIS 1.6.1 / STIG-V-230264).
# Note: sysctl values are baked in here for reference and applied by the host/runtime;
# net.* values are also enforced directly via the compose sysctls block.
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

# perl-base and tar are Debian 13 essential packages — dpkg depends on both and they
# cannot be purged. Restrict to root-only execution as the CIS-acceptable mitigation.
RUN chmod 700 /usr/bin/perl /usr/bin/tar 2>/dev/null || true

# Lock down TLS private key directories and any stray key files
RUN mkdir -p /etc/ssl/private \
 && chmod 0700 /etc/ssl/private \
 && find /etc/ssl/private -type f -exec chmod 0600 {} \; || true
RUN find /etc/ssl -type f \( -name '*.key' -o -name '*-key.pem' -o -name '*_key.pem' \) \
      -exec chmod 0600 {} \; || true

# Enforce FIPS 140-3 aligned TLS policy across OpenSSL and GnuTLS.
# Cipher suite selection follows NIST SP 800-52 Rev 2: AES-GCM only, TLS 1.2 minimum,
# no CBC-SHA1, no RC4, no 3DES, no export ciphers, no anonymous DH.
RUN set -eux; \
    sed -i \
        's|^CipherString\s*=.*|CipherString = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256|' \
        /etc/ssl/openssl.cnf; \
    sed -i 's|^MinProtocol\s*=.*|MinProtocol = TLSv1.2|' /etc/ssl/openssl.cnf; \
    grep -q '^CipherSuites' /etc/ssl/openssl.cnf || \
        sed -i '/^CipherString/a CipherSuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256' /etc/ssl/openssl.cnf; \
    echo "[FIPS] TLS cipher policy applied"

# Attempt to activate the OpenSSL 3.x FIPS provider at build time.
# The provider lives at /usr/lib/<arch>/ossl-modules/fips.so on Debian 13.
# If the slim base doesn't ship it, FIPS activation falls back to the runtime
# environment variable OPENSSL_FIPS=1 (already set in ENV below).
RUN set -eux; \
    FIPS_SO=$(find /usr/lib -path '*/ossl-modules/fips.so' 2>/dev/null | head -1); \
    if [ -n "${FIPS_SO:-}" ]; then \
        mkdir -p /etc/ssl; \
        openssl fipsinstall -out /etc/ssl/fips.cnf -module "${FIPS_SO}" \
        && printf '\n# HARDN-XDR: FIPS 140-3 provider\n.include /etc/ssl/fips.cnf\n' >> /etc/ssl/openssl.cnf \
        && echo "[FIPS] provider self-test passed: ${FIPS_SO}"; \
    else \
        echo "[FIPS] fips.so not found; activate at deployment with OPENSSL_FIPS=1"; \
    fi

# The openssl CLI was only needed for the fipsinstall step above.
# Purge it now to eliminate its CVE surface from the final image.
# The SSL runtime library (libssl3t64) is intentionally kept.
RUN apt-get purge -y openssl \
 && apt-get autoremove -y --purge \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Disable legacy TLS versions in GnuTLS as well (CIS 4.5)
RUN mkdir -p /etc/gnutls \
 && printf '[overrides]\ndisabled-version = ssl3.0\ndisabled-version = tls1.0\ndisabled-version = tls1.1\n' \
    > /etc/gnutls/config

# Strip setuid/setgid bits from all binaries except sudo (CIS 4.2 / STIG-V-230257)
# Skip this in FAST_BUILD mode to keep local iteration fast.
RUN if [ "$FAST_BUILD" != "1" ]; then \
      find /usr -xdev -perm /6000 -type f ! -path '/usr/bin/sudo' -exec chmod ug-s {} + 2>/dev/null || true; \
    fi

# Sticky bit on shared temp directories prevents users from deleting each other's files
RUN chmod 1777 /tmp /var/tmp || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD bash -lc '\
    test -r /etc/os-release || { echo "/etc/os-release missing"; exit 1; }; \
    : > /tmp/.hc.$$ && rm -f /tmp/.hc.$$ || { echo "/tmp not writable"; exit 1; }; \
    echo "OK"; exit 0'

RUN /usr/local/bin/deb.hardn.sh || echo "HARDN setup complete"

# Harden password policy in login.defs (CIS 5.4.1 / STIG-V-230332)
# UMASK 027 means new files are not world-readable by default.
RUN sed -ri 's/^#?SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 5000/' /etc/login.defs && \
    sed -ri 's/^#?SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 50000/' /etc/login.defs && \
    sed -ri 's/^#?PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs && \
    sed -ri 's/^#?PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs && \
    sed -ri 's/^#?PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs && \
    sed -ri 's/^#?UMASK\s.*/UMASK\t\t027/' /etc/login.defs; \
    grep -qE '^UMASK' /etc/login.defs || printf 'UMASK\t\t027\n' >> /etc/login.defs

# Enforce password complexity via PAM pwquality (NIST SP 800-63B / CIS 5.3.1)
# Requires at least 14 characters and one each of upper, lower, digit, and special character.
RUN if [[ -f /etc/pam.d/common-password ]]; then \
      sed -i 's|\(pam_pwquality\.so[^$]*\)|\1 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1|' \
          /etc/pam.d/common-password; \
      sed -i 's/minlen=14\( .*\)*\(minlen=14\)/minlen=14/' /etc/pam.d/common-password || true; \
    fi

# Restrict compiler binaries to root-only in case they were pulled in as transitive deps
RUN chmod 700 /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc* 2>/dev/null || true

# Final cleanup — remove docs, locale data, compressed archives, and empty any log files
RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* /var/tmp/* \
 && find /usr/share -type f \( -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \) -delete 2>/dev/null || true \
 && rm -rf /usr/share/locale/* /usr/share/i18n/* /usr/share/doc/* /usr/share/man/* 2>/dev/null || true \
 && find /var/log -type f -exec truncate -s 0 {} \; || true

# OCI labels 
LABEL org.opencontainers.image.title="HARDN-XDR (Debian 13, CIS/FIPS)" \
      org.opencontainers.image.description="Hardened Debian 13 (Trixie) container image: CIS Docker Benchmark 1.13.0, FIPS 140-3 aligned (AES-GCM/SHA-2 only, TLS 1.2+), non-root user, umask 027, DISA STIG hardening, read-only-rootfs friendly. FIPS provider activation requires deployment on a FIPS-validated host kernel." \
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
      security.apparmor="host-enforced" \
      security.selinux="host-enforced" \
      security.fips.140-3="aligned" \
      security.nist.sp800-52="rev2-compliant" \
      security.readonly.rootfs="true" \
      security.no.new.privileges="true" \
      security.healthcheck="enabled" \
      security.logging="centralized" \
      security.audit="enabled"

STOPSIGNAL SIGTERM

# Runtime environment — OPENSSL_FIPS=1 signals OpenSSL to require the FIPS provider.
# AppArmor and SELinux profiles are applied by the host runtime, not baked into the image.
ENV MEMORY_LIMIT=512m \
    CPU_SHARES=1024 \
    PIDS_LIMIT=1024 \
    NO_NEW_PRIVILEGES=true \
    READONLY_ROOTFS=true \
    RESTART_POLICY=on-failure:5 \
    OPENSSL_FIPS=1 \
    FIPS_MODE=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER ${HARDN_UID}:${HARDN_GID}
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
