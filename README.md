
![hardn](src/sources/C20B6DE6-87CA-4439-A74F-3CD2D4BF5A82.png)

<p align="center">
 

# Security International Group - Hardened Docker Image

A security-hardened Debian-based Docker image that can host applications while maintaining CIS compliance and security best practices.

 ## Docker Hub

[![Docker Pulls](https://img.shields.io/docker/pulls/tburns0321/hardn-docker)](https://hub.docker.com/r/tburns0321/hardn-docker)

**Pull from Docker Hub:**
```bash
docker pull tburns0321/hardn-docker:1.0.21
```
## Quick Start

### 1. Clone and Build
```bash
git clone https://github.com/Security-International-Group/HARDN_DOCKER.git
cd HARDN_DOCKER
docker-compose build
```

### 2. Run the Container
```bash
docker-compose up -d
```

### 3. Access Your App
The application will be available at:
- **http://localhost:8082**

Test it:
```bash
curl http://localhost:8082
# Should return: "Hello, World : ) This application is running inside the hardened container."
```

## Security Features

### CIS Docker Benchmark Compliance
- **Automated Security Hardening**: CIS Docker 1.13.0 compliant configuration
- **Docker Bench Security Integration**: Built-in security auditing and remediation
- **Host-Level Security**: Scripts for Docker daemon and host security configuration

### Key Security Measures
-  **Non-root execution** (runs as uid=10001)
-  **AppArmor profiles** for container security
-  **Seccomp profiles** for syscall restrictions
-  **Memory and resource limits** enforced
-  **Read-only root filesystem** with tmpfs mounts
-  **TLS encryption** for Docker daemon
-  **Audit logging** for Docker events
-  **No new privileges** capability
-  **User namespace remapping** enabled

### Hardening Scripts
The image includes comprehensive hardening scripts in `/sources/`:
- `compliance/` - OpenSCAP and cron-based compliance monitoring
- `memory/` - Memory protection and partition management (`part.sh`)
- `network/` - Network security and intrusion detection
- `privilege/` - PAM security and privilege escalation prevention
- `security/` - Core security configurations and integrity monitoring

## Security Model

### Build-Time Hardening
- All security scripts execute during Docker build as root
- System configurations are applied and locked down
- Hardening completion marker is created
- Image is prepared for secure runtime execution

### Runtime Security
- Container runs as non-root user (uid=10001)
- Hardening scripts are skipped (already completed)
- Application executes with minimal privileges
- Security policies remain enforced

## Application Deployment

The container includes a sample web application using busybox httpd that demonstrates the image can successfully host applications. To deploy your own application:

1. Replace `/usr/local/bin/simple-server` with your application
2. Update the Dockerfile CMD if needed
3. Rebuild the image

The container runs as a non-root user with comprehensive security hardening while maintaining full application functionality.

---

*Built with security and compliance in mind for production deployments.*
## Architecture

```bash
hardn-xdr/
├─ Dockerfile                    # Container build with security hardening
├─ docker-compose.yml           # Container orchestration with security settings
├─ deb.hardn.sh                 # Main hardening script (calls all /sources scripts)
├─ entrypoint.sh                # Container entrypoint with privilege dropping
├─ health_check.sh              # Health monitoring and compliance checks
├─ smoke_test.sh                # Pre-deployment compliance verification
├─ src/sources/                 # Security hardening scripts directory
│  ├─ compliance/
│  │  ├─ openscap-registry.sh   # OpenSCAP compliance scanning
│  │  └─ cron.sh               # Automated compliance monitoring
│  ├─ memory/
│  │  ├─ clamav.sh            # ClamAV antivirus configuration
│  │  ├─ part.sh              # Docker partition & memory security
│  │  └─ protection.sh        # Memory protection & buffer overflow prevention
│  ├─ network/
│  │  ├─ aide.sh              # AIDE integrity monitoring
│  │  └─ tripwire.sh          # Tripwire intrusion detection
│  ├─ privilege/
│  │  ├─ access.sh            # PAM security & user access controls
│  │  └─ rkhunter.sh          # rkhunter rootkit detection
│  └─ security/
│     ├─ apparmor.sh          # AppArmor profile configuration
│     ├─ docker-daemon.sh     # Docker daemon security setup
│     ├─ host-config.sh       # Host security configuration
│     ├─ image-security.sh    # Container image security
│     ├─ integrity.sh         # File integrity monitoring
│     ├─ security.sh          # Core security configurations
│     ├─ selinux.sh           # SELinux policy configuration
│     └─ docker-daemon.sh     # Docker daemon security (TLS, audit, etc.)
├─ README.md                    # This documentation
└─ SECURITY-REMEDIATION.md     # Security hardening guide
```
