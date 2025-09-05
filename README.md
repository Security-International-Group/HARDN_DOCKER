![hardn-docker](src/sources/C20B6DE6-87CA-4439-A74F-3CD2D4BF5A82.png)
# HARDN_Debian_Docker_image
- A Deployable Debian 13: trixie , HARDN/STIG/CIS compliant Dockerfile image
---
[![Docker](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/docker-publish.yml)
[![Trivy](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/trivy.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/hardn_debian_docker_image/actions/workflows/trivy.yml)

## Build
```bash
# Build 
docker build -t hardn-xdr:deb13 .

# Remove any previous container 
docker rm -f hardn-xdr 2>/dev/null || true

# Run 
docker run --name hardn-xdr -d hardn-xdr:deb13

```

# Testing 

- To test the current runtime status and CIS benchmarks,
install and run "smoke_test.sh" and this will provide the testing benchmarks loaded into the OS. 
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
