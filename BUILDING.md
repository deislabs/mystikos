# Mystikos Build Instructions

This document contains instructions to build mystikos on Linux

## Building from source

Mystikos is compatible with **Ubuntu 20.04**. It may be compiled with or
without SGX capability.

## Install the prerequisites

```
sudo apt update
sudo apt install -y git make libmbedtls-dev docker.io
sudo systemctl start docker
sudo systemctl enable docker && sudo chmod 666 /var/run/docker.sock
```

## Clone, build, and install Mystikos

```
git clone https://github.com/deislabs/mystikos
cd mystikos && make
sudo make install
export PATH=$PATH:/opt/mystikos/bin
```

The build process will automatically install all prerequisite for OE SDK first,
including the Intel SGX driver and Intel Platform Software, and then build the
project. Finally, it installs the build outputs to `/opt/mystikos`.

Mystikos can be used to run applications on a non-SGX-capable Ubuntu 20.04
machine while running with the Linux target (simulation mode). Obviously you
need an SGX-capable machine to try out the SGX target. There are multiple ways
which you might procure an SGX-capable machine, including but not limited to:
- buy or build an Intel NUC (TODO: include specific model number)
- use a [`DCsv2`-series (from DC1s_v2 up to DC8s_V2) VM on Azure](https://aka.ms/accgetstarted)
- or use another cloud provider which also has SGX support
- use your own servers
