#!/usr/bin/env bash
set -exo pipefail

echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs | xargs) main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
wget https://packages.microsoft.com/keys/microsoft.asc
sudo apt-key add microsoft.asc
sudo apt-get -o DPkg::Lock::Timeout=3 -o APT::Acquire::Retries=3 update
sudo apt-get -o DPkg::Lock::Timeout=3 -o APT::Acquire::Retries=3 -y install azure-cli
