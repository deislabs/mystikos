# Mystikos Build Instructions

This document contains instructions to build mystikos on Linux

## Building from source

Mystikos *must* be built on **Ubuntu 18.04**. This is a limitation of [Open
Enclave SDK](github.com/openenclave/openenclave).It may be compiled with or
without SGX capability.

## Install the prerequisites

```
sudo apt update && sudo apt upgrade
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

Mystikos can be used to run applications on a non-SGX-capable Ubuntu 18.04
machine while running with the Linux target (simulation mode). Obviously you
need an SGX-capable machine to try out the SGX target. For that, we recommend
either an [ACC VM](https://aka.ms/accgetstarted) or a bare-metal machine with
SGX support.
