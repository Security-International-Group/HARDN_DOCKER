# HARDN_Debian_Docker_image
A Deployable Debian 12, HARDN/STIG compliant Dockerfile image 

## Build
```bash
# Build 
docker build -t hardn-xdr:deb12 .

# Remove any previous container 
docker rm -f hardn-xdr 2>/dev/null || true

# Run 
docker run --name hardn-xdr -d hardn-xdr:deb12
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
