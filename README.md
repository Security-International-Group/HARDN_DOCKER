<p align="center">
  <img src="src/sources/C20B6DE6-87CA-4439-A74F-3CD2D4BF5A82.png" alt="hardn-docker" width="690"/>
  <br>
  <a href="https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml">
    <img src="https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml/badge.svg" alt="Docker"/>
  </a>
  <a href="https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/trivy.yml">
    <img src="https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/trivy.yml/badge.svg" alt="Trivy"/>
  </a>
</p>

<div align="center">
  <h1>HARDN_Debian_Docker_image</h1>


</div>
# HARDN-XDR Hardened Docker Image

A security-hardened Debian-based Docker image that can host applications while maintaining CIS compliance and security best practices.

## Docker Hub

[![Docker Pulls](https://img.shields.io/docker/pulls/tburns0321/hardn-xdr)](https://hub.docker.com/r/tburns0321/hardn-xdr)

**Pull from Docker Hub:**
```bash
docker pull tburns0321/hardn-xdr:latest
```

## Quick Start

### 1. Build the Image
```bash
git clone https://github.com/Security-International-Group/HARDN_DOCKER.git
cd HARDN_DOCKER
docker build -t hardn-xdr .
```

### 2. Run the Container
```bash
# Simple run
docker run -d -p 8080:5000 --name hardn-app hardn-xdr

# Or use docker-compose (recommended)
docker-compose up -d
```

### 3. Access Your App
The Flask application will be available at:
- **http://localhost:8080** (when using docker-compose)
- **http://localhost:8080** (when using docker run with `-p 8080:5000`)

Test it:
```bash
curl http://localhost:8080
# Should return: "Hello, World : ) This application is running inside the hardened container."
```

## Application Deployment

The container includes a sample Flask application (`src/app.py`) that demonstrates the image can successfully host applications. To deploy your own application:

1. Replace `src/app.py` with your application code
2. Update the Dockerfile CMD if needed
3. Rebuild the image

The container runs as a non-root user with comprehensive security hardening while maintaining full application functionality.

## Security Features

- ✅ CIS Docker Benchmark v1.13.0 compliant
- ✅ Non-root user execution
- ✅ Read-only root filesystem
- ✅ AppArmor security profiles
- ✅ No new privileges
- ✅ Memory and CPU limits
- ✅ Comprehensive logging

## Project Links

- **GitHub Repository**: https://github.com/Security-International-Group/HARDN_DOCKER
- **Docker Hub**: https://hub.docker.com/r/tburns0321/hardn-xdr
- **Security Policy**: [View Security Guidelines](SECURITY.md)

---

*Built with security and compliance in mind for production deployments.*

<div align="center">
  <h1>HARDN_Debian_Docker_image</h1>


</div>

## Overview
- **Base OS:** Debian 13 “Trixie,” latest stable release.
- **Security Hardened:** Automated removal of OS and container CVEs during build and runtime using `deb.hardn.sh`.
- **Compliance Goals:** Built to exceed industry standards (HARDN, STIG, CIS).
- **Zero CVE Builds:** Containers are continuously monitored and updated to ensure no known vulnerabilities using `.github/workflows/trixie.yml`.
- **Read-Only & tmpfs Support:** Example run commands demonstrate best practices for least privilege and ephemeral storage.
- **Automated CI/CD:** Integrated with GitHub Actions for build validation and vulnerability scanning (Trivy).

### Deployments
- Deploy as a secure base image for microservices and critical workloads.
- Ideal for regulated environments demanding high compliance and security assurance.
- Continuous integration in DevSecOps pipelines.

## Packages
- Current GHCR-OCI [Package](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/pkgs/container/hardn_debian_docker_image)
- [Docker Hub](https://hub.docker.com/r/tburns0321/hardn-xdr)



## Architecture

```bash
hardn-xdr-deb/
├─ Dockerfile                    # Container build with security hardening
├─ docker-compose.yml           # Container orchestration with security settings
├─ daemon.json                  # Docker daemon CIS compliance configuration
├─ configure-docker-daemon.sh   # Host Docker daemon setup script
├─ deb.hardn.sh                 # Main hardening script
├─ entrypoint.sh                # Container entrypoint with privilege dropping
├─ smoke_test.sh                # Pre-deployment compliance checks
├─ README.md                    # Documentation
├─ src/
│  └─ sources/                  # Security hardening scripts
│     ├─ compliance/            # CIS compliance and OpenSCAP
│     ├─ memory/                # Memory protection and monitoring
│     ├─ network/               # Network security and firewall
│     ├─ privilege/             # Access controls and PAM
│     └─ security/              # AppArmor, SELinux, integrity
└─ .github/
   └─ workflows/                # CI/CD pipelines
      ├─ build-and-publish.yml  # Docker build and publish
      └─ trivy.yml             # Vulnerability scanning
```

### Release
Here you can find the latest GHCR Release.
- [Releases](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/releases)

## Build
```bash
# Remove any previous container
docker rm -f hardn-xdr 2>/dev/null || true
# Build
docker build -t hardn-xdr:deb13 .
# Run
docker run --name hardn-xdr -d hardn-xdr:deb13

# read only + tmpfs
docker rm -f hardn-xdr 2>/dev/null || true
docker run --name hardn-xdr -d \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,mode=1777,size=64m \
  --tmpfs /run:rw,noexec,nosuid,mode=0755,size=16m \
  --tmpfs /home/hardn:rw,mode=0755,size=32m \
  --tmpfs /opt/hardn-xdr:rw,mode=0755,size=64m \
  hardn-xdr:deb13
```
## GHCR Package
### Pull and run published image from GHCR.io
```
docker pull ghcr.io/openSource-for-freedom/hardn_debian_docker_image:deb13
docker run --name hardn-xdr -d ghcr.io/openSource-for-freedom/hardn_debian_docker_image:deb13

```

## CIS Docker Benchmark v1.13.0 Compliance

### Benchmark resolved ISSUES (Host + Container)
- **2.1** - Network traffic restricted between containers (`icc: false`)
- **2.8** - User namespace support enabled (`userns-remap: default`)
- **2.11** - Authorization enabled (`authorization-plugin`)
- **2.12** - Centralized logging configured (`log-driver`)
- **2.14** - Live restore enabled (`live-restore: true`)
- **2.15** - Userland Proxy disabled (`userland-proxy: false`)
- **2.18** - No new privileges enforced (`no-new-privileges: true`)
- **3.15** - Docker socket ownership fixed (`root:docker`)
- **4.5** - Content trust enabled (`DOCKER_CONTENT_TRUST=1`)
- **5.1** - AppArmor profile enabled (integrated into build)
- **5.11** - CPU priority set appropriately (cpu_shares, cpu_quota configured)

### CONTAINER-SPECIFIC (Runtime Verified)
- **4.1** - Non-root user created (`hardn` user)
- **4.2** - Trusted base image (Debian Trixie Slim)
- **4.6** - Health check configured
- **5.2** - NoNewPrivs set
- **5.4** - Non-privileged execution
- **5.12** - Read-only root filesystem

## Docker Daemon Configuration

### Why Separate Host Configuration?
Some CIS requirements must be configured at the Docker daemon (host) level because they affect all containers globally:

- **Network isolation** (`icc: false`) - Controls inter-container communication
- **Logging configuration** - Centralized logging for all containers
- **Live restore** - Service continuity during daemon restarts
- **Socket ownership** - Host file permissions
- **Content trust** - Host environment variable

```

### Files
- `daemon.json` - Minimal host-level Docker daemon configuration
- `docker-compose.yml` - Container-specific security settings

## Compliance Testing
- The file `smoke_test.sh` deploys a high level compliance check pre-depolymnet to GHCR/Ci.
```
echo "=========================================="
echo " HARDN-XDR Container Health Check"
echo " CIS Docker Benchmark 1.13.0 Compliance"
echo "=========================================="

# CIS 4.1: Ensure a user for the container has been created...
```


## Security
- Reporting a Vulnerability or compliance > [Security Policy](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/security/policy)

## DevOPs Testing and Workspace
- Github https://github.com/Security-International-Group
