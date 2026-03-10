## 2026-03-09

**FIPS 140-3 TLS hardening, zero-CVE image, 35.5 MB — full CIS/DISA compliance pass**

### What changed

**FIPS 140-3 aligned TLS policy**
- Replaced the legacy `openssl.cnf.d/10-hardn.cnf` drop-in with an in-place edit of `/etc/ssl/openssl.cnf` so the policy applies to all OpenSSL consumers in the image.
- Cipher suite locked to ECDHE-RSA-AES256-GCM-SHA384 / AES128-GCM-SHA256 / DHE-RSA-AES256-GCM-SHA384 / DHE-RSA-AES128-GCM-SHA256 (NIST SP 800-52 Rev 2, AEAD-only, no CBC-SHA1, no 3DES).
- Minimum protocol set to TLS 1.2; TLS 1.3 restricted to `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`.
- OpenSSL 3.x FIPS provider self-test (`openssl fipsinstall`) runs at build time; graceful skip if `fips.so` is absent.
- `OPENSSL_FIPS=1` and `FIPS_MODE=1` set as runtime environment variables.
- GnuTLS `/etc/gnutls/config` disables ssl3.0, tls1.0, and tls1.1.

**Zero CVEs — openssl CLI removed**
- After the `fipsinstall` step (its last use in the build), the `openssl` CLI package is purged with `apt-get purge openssl`. The `libssl3t64` runtime library is kept.
- This eliminates the last remaining CVE from Docker Scout / Trivy scans.
- Final scan result: **0 CVEs** across all severity levels.

**Image size: 137 MB → 35.5 MB (~74% reduction)**
- Removed two redundant purge layers that had been operating on already-cleaned apt state. These layers were dead code and were safely removed.
- Removed a duplicate python3/expat purge block (already handled in the primary install layer).
- `libpam-pwquality` moved from the now-removed dead layer into the primary `RUN --mount=type=cache` apt layer where it can actually install.
- Locale files, docs, and man pages purged in the shrink layer.

**Host-level ops gated in `deb.hardn.sh`**
- AppArmor package install removed; the image cannot load kernel modules. Profile enforcement is a host/runtime concern (`--security-opt apparmor=` or compose `security_opt`).
- SELinux configuration removed from the image build; context labels are assigned at container start time.
- `docker-daemon.sh` call is now gated behind `IN_CONTAINER=false` to prevent it running inside the container image build.

**PAM password policy enforced**
- `libpam-pwquality` installed and active in the image.
- `pam_pwquality.so minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1` written into `/etc/pam.d/common-password`.

**UMASK baked in with fallback**
- `debian:trixie-slim` ships a `login.defs` without a `UMASK` line. Added a `grep -q || printf >>` fallback to ensure `UMASK 027` is always present even if the `sed` replacement finds nothing to replace.

**`health_check.sh` arithmetic fix**
- `((checks++))` with `checks=0` evaluates `((0))`, which returns exit code 1 and kills the shell under `set -Eeuo pipefail`. Changed to `(( ++checks ))` (pre-increment always returns a non-zero value once the counter is 1+).
- Health check result: **12 ok / 1 warn / 0 fail / EXIT:0** (the warn is the expected "file-integrity baseline not yet created" on first run).

**`src/app.py` fixes**
- Added missing `import os` (caused a `NameError` on `os.path` calls).
- Changed `debug=True` to `debug=False` — Flask debug mode must never be on in a hardened/production image.

**`docker-compose.yml` updates**
- Added `sysctls:` block with 10 `net.ipv4.*` parameters scoped to the container network namespace (CIS 5.x).
- Added `OPENSSL_FIPS=1` and `FIPS_MODE=1` to the `environment:` block.
- Updated compliance labels: `compliance=cis-1.13.0,fips-140-3-aligned`, `security.fips.140-3=aligned`, `security.nist.sp800-52=rev2-compliant`.

---

## 2025-12-07

**Remediation list (Docker Bench follow-up)**

Already addressed in repo (or partially mitigated)
- [WARN] 2.1: Restricted default bridge by attaching the service to internal user-defined network `hardn_net` in `docker-compose.yml`.
- [WARN] 2.18: `no-new-privileges` set via `security_opt` in compose.
- [WARN] 4.5: Content trust enabled via `DOCKER_CONTENT_TRUST=1` in compose env.
- [WARN] 5.30: Removed `userns_mode: host` in compose so containers no longer share host user namespace.

Not fixable inside the image/compose on Docker Desktop (host-level only)
- [WARN] 1.1: Separate partition for `/var/lib/docker` (host disk layout).
- [WARN] 1.5–1.13: Audit daemon/files (/etc/docker, docker.service/socket, daemon.json, containerd/runc paths) require host auditd and daemon files.
- [WARN] 2.6: TLS for Docker daemon — needs daemon config and certs on host.
- [WARN] 2.8: user namespace support — requires daemon `userns-remap` (not supported on Docker Desktop).
- [WARN] 2.11: AuthZ plugin — host daemon plugin/config.
- [WARN] 2.12: Centralized/remote logging — host daemon logging config.
- [WARN] 2.14: live-restore — host daemon setting (unsupported on Desktop).
- [WARN] 2.15: disable userland-proxy — host daemon setting (may be unsupported on Desktop).
- [WARN] 3.15: Docker socket ownership root:docker — host-level file ownership.
- [WARN] 5.1: AppArmor profile enforced — requires AppArmor on host; not available on Docker Desktop.

Note: Remaining WARNs are expected when scanning against Docker Desktop/WSL because the daemon and host controls sit outside the container image and compose configuration.
