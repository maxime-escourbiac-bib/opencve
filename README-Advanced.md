# Advanced CVE

## How to Install AdvancedCVE for development

```bash
cd docker
export CERT_IST_REPO=https://<user>:<pat>@github.com/<repo>
./install-dev.sh prepare
./install-dev.sh start-docker-stack
./install-dev.sh clone-repositories
unset CERT_IST_REPO
./install-dev.sh create-superuser
./install-dev.sh import-opencve-kb
./install-dev.sh import-advancedcve-kb
./install-dev.sh start-opencve-dag
```
