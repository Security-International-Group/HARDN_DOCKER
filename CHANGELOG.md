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
