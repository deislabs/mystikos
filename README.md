![Mystikos](./art/light/logo-horizontal/logo-horizontal.png)

## What is Mystikos?
**Mystikos** is a runtime and a set of tools for running Linux applications
in a hardware trusted
execution environment (TEE). The current release supports **Intel &reg; SGX**
while other TEEs may be supported in future releases.

## Goals

- Enable protection of application code and data while in memory through the
  use of hardware TEEs. This should be combined with proper key management,
  attestation and hardware roots of trust, and encryption of data at rest and
  in transit to protect against other threats which are out of scope for this
  project.
- Streamline the process of lift-n-shift applications, either native or
  containerized, into TEEs, with little or no modification.
- Allow users and application developers control over the makeup of the trusted
  computing base (TCB), ensuring that all components of the execution environment
  running inside the TEE are open sourced with permissive licenses.
- Simplify re-targeting to other TEE architectures through a plugin
  architecture.

## Architecture

**Mystikos** consists of the following components:
- a C-runtime based on [musl libc](https://musl.libc.org), but is glibc compatible
- a "lib-os like" kernel
- the kernel-target interface (TCALL)
- a command-line interface
- some related utilities

Today, two target implementations are provided:
- The **SGX** target (based on the [Open Enclave
  SDK](https://github.com/openenclave/openenclave))
- The **Linux** target (for verification on non-SGX platforms)

The minimalist kernel of Mystikos manages essential computing resources
inside the TEE, such as CPU/threads, memory, files, networks, etc. It handles
most of the syscalls that a normal operating system would handle (with
[limits](doc/syscall-limitations.md)).  Many syscalls are handled directly by the
kernel while others are delegated to the target specified while launching
Mystikos.

![](./arch.png)


# Installation Guide for Ubuntu 18.04

## Install Intel SGX DCAP Driver if necessary

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
wget https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.35.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```
## Add Intel and Microsoft's repositories & install the required packages

```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

sudo apt update

sudo apt -y install libsgx-enclave-common libsgx-dcap-ql libsgx-dcap-ql-dev libsgx-quote-ex az-dcap-client libmbedtls-dev

curl -sSL https://get.docker.com/ | sh
```

## Download Mystikos

You can [download the latest build here](https://github.com/deislabs/mystikos/releases)
then simply decompress it, add it to your path, and run it.

```
# change this to match the latest version
LATEST='0.2.0'
RELEASE="mystikos-${LATEST}-x86_64"

# this will create the "mystikos" directory within your current working directory
curl -sSL --ssl https://github.com/deislabs/mystikos/releases/download/v${LATEST}/${RELEASE}.tar.gz | tar -xzf -

# you can use mystikos from your home directory, or any path
export PATH="$PATH:$(pwd)/mystikos/bin"
```

## Install From Source

You may also [build Mystikos from source](BUILDING.md). The build process
will install the SGX driver and SGX-related packages for you.

**NOTE** that Mystikos can only be built on **Ubuntu 18.04**. We are working
on bringing Mystikos to **Ubuntu 20.04**.


# Quick Start Docs

Eager to get started with Mystikos? We've prepared a few guides, starting from
a simple "hello world" C program and increasing in complexity, including
demonstrations of DotNet and Python/NumPy.

Give it a try and let us know what you think!

## Simple Applications

- A Simple "Hello World" in C: [click here](doc/user-getting-started-c.md)
- A Simple "Hello World" in Rust: [click here](doc/user-getting-started-rust.md)
- Packaging your "Hello World" app in Docker: [click
  here](doc/user-getting-started-docker-c++.md)
- Introducing Enclave Configuration with a DotNet program: [click
  here](doc/user-getting-started-docker-dotnet.md)
- Running Python & NumPy for complex calculations: [click
  here](doc/user-getting-started-docker-python.md)

## Enclave Aware Applications

Sometimes, you want to take advantage of specific properties of the Trusted
Execution Environment, such as attestation. The following example shows how to
write a C program which changes its behaviour when it detects that it has been
securely launched inside an SGX enclave.

- Getting started with a TEE-aware program: [click
  here](doc/user-getting-started-tee-aware.md)

## More Docs!

We've got plans for a lot more documentation as the project grows, and we'd
love your feedback and contributions, too.

- Key features of Mystikos: [click here](doc/key-features.md)
- Deep dive into Mystikos architecture: [coming soon]
- How to implement support for a new TEE: [coming soon]
- Kernel limitations: [click here](doc/kernel-limitations.md)
- Multi-processing and multi-threading in Mystikos and limitations: [coming
  soon]


# Developer Docs

Looking for information to help you with your first PR? You've found the right
section.

- Developer's jump start guide: [click here](doc/dev-jumpstart.md)
- Signing and packaging applications with Mystikos: [click
  here](doc/sign-package.md)
- Release management: [click here](doc/releasing.md)
- Notable unsupported kernel features and syscalls: [coming soon]

For more information, see the [Contributing Guide](CONTRIBUTING.md).


# Licensing

This project is released under the [MIT License](LICENSE).

# Reporting a Vulnerability

**Please DO NOT open vulnerability reports directly on GitHub.**

Security issues and bugs should be reported privately via email to the
[Microsoft Security Response Center](https://www.microsoft.com/en-us/msrc)
(MSRC) at secure@microsoft.com. You should receive a response within 24 hours.
If for some reason you do not, please follow up via email to ensure we received
your original message.


# Code of Conduct

This project has adopted the
[Microsoft Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
All participants are expected to abide by these basic tenets to ensure that the
community is a welcoming place for everyone.

# Test change. Please ignore & do not merge..
