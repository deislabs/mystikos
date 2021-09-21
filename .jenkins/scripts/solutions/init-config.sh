echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ bionic main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
wget https://packages.microsoft.com/keys/microsoft.asc
sudo apt-key add microsoft.asc
sudo apt-get update
