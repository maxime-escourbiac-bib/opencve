# Advanced CVE

## How to Install AdvancedCVE for development

```bash
cd docker
./install-dev.sh prepare
./install-dev.sh start-docker-stack
./install-dev.sh clone-repositories
./install-dev.sh create-superuser
./install-dev.sh import-opencve-kb
./install-dev.sh start-opencve-dag
export CERT_IST_REPO=https://<user>:<pat>@github.com/<repo>
./install-advanced.sh
unset CERT_IST_REPO
```
