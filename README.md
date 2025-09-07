![hardn-docker](src/sources/C20B6DE6-87CA-4439-A74F-3CD2D4BF5A82.png)
# HARDN_Debian_Docker_image
- Debian 13: trixie , HARDN/STIG/CIS compliant Dockerfile image
---
[![Docker](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml)
[![Trivy](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/trivy.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/trivy.yml)

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

# Pull and run published image from GHCR

docker pull ghcr.io/openSource-for-freedom/hardn_debian_docker_image:deb13
docker run --name hardn-xdr -d ghcr.io/openSource-for-freedom/hardn_debian_docker_image:deb13

```

## Testing 
![docker](src/sources/docker.png)
- Currently "0" CVE builds - OS and Container.
- deb.hardn.sh deploys a slim security slice into the Container which fully removes all local Debian 13, and Docker Image CVE's during build and run. 
- CVE-2025-45582 — Medium Severity (CVSS 3.1: 4.1) does not pertain to this package. Tar is not a utilized dependacy but does exist in Debian 13 in its initial state. 

---
## Architecture 

```bash
hardn-xdr-deb/
├─ Dockerfile
├─ deb.hardn.sh
├─ entrypoint.sh
├─ smoke_test.sh
├─ README.md
├─ .github/
│  └─ workflows/
│     └─ build-and-publish.yml
```
