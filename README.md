# HARDN_Debian_Docker_image
- A Deployable Debian 13: trixie , HARDN/STIG/CIS compliant Dockerfile image
---
[![Docker](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml)
## Build
```bash
# Build 
docker build -t hardn-xdr:deb12 .

# Remove any previous container 
docker rm -f hardn-xdr 2>/dev/null || true

# Run 
docker run --name hardn-xdr -d hardn-xdr:deb13
```
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
│     └─ ci.yml
```
