# HARDN_RHEL_Docker_image
A Deployable RHEL 9, HARDN/STIG/FIPS compliant Dockerfile image 

## Build
```bash
docker build -t ghcr.io/Opensource-for-freedom/hardn-xdr:rhel9 .
```
---
## Architecture 

```bash
hardn-xdr-rhel/
├─ Dockerfile
├─ rhel.hardn.sh
├─ entrypoint.sh
├─ smoke_test.sh
├─ README.md
├─ .github/
│  └─ workflows/
│     └─ ci.yml
```
