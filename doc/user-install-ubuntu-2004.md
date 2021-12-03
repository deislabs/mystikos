# Installation Guiide for Ubuntu 20.04

## 1. Install Intel Drivers

### Install Intel SGX DCAP Driver if necessary

Some distributions come with the SGX driver already installed; if it is,
you don't need to re-install it. You can verify this by running:

```bash
dmesg | grep -i sgx
```

If the output is blank, install the driver manually by downloading it from Intel.

> NOTE: The script below may not refer to the latest Intel SGX DCAP driver.
> Check [Intel's SGX Downloads page](https://01.org/intel-software-guard-extensions/downloads)
> to see if a more recent SGX DCAP driver exists.

```bash
sudo apt -y install dkms
wget https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.36.2.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```
### Add Intel and Microsoft's repositories & install the required packages

```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

sudo apt update

sudo apt -y install libsgx-enclave-common libsgx-dcap-ql libsgx-dcap-ql-dev libsgx-quote-ex az-dcap-client libmbedtls-dev

curl -sSL https://get.docker.com/ | sh
```

## 2. Download and Install Mystikos

### Download and Install from GitHub

You can [download the latest build here](https://github.com/deislabs/mystikos/releases).

**Tarball installation**

```
# change this to match the latest version
LATEST='0.7.0'
RELEASE="Ubuntu-2004_mystikos-${LATEST}-x86_64"

# this will create the "mystikos" directory within your current working directory
curl -sSL --ssl https://github.com/deislabs/mystikos/releases/download/v${LATEST}/${RELEASE}.tar.gz | tar -xzf -

# you can use mystikos from your home directory, or any path
export PATH="$PATH:$(pwd)/mystikos/bin"
```

**Debian package installation**

```
# change this to match the latest version
LATEST='0.7.0'
RELEASE="Ubuntu-2004_mystikos-${LATEST}-x86_64"

# this will install Mystikos in /opt/mystikos
curl -sSL --ssl https://github.com/deislabs/mystikos/releases/download/v${LATEST}/${RELEASE}.deb -O
sudo dpkg -i ${RELEASE}.deb
rm ${RELEASE}.deb

```
*Note:* To remove Mystikos installed with a Debian package, run the command: `sudo apt remove mystikos`
