# Open LibOS

**Open LibOS** is a set of tools for running user applications in a trusted
execution environment (TEE). The current release supports **Intel &reg; SGX**
while other TEEs may be supported in future releases.

## Goals

- Protect user data throughout its lifecyle (at rest, in flight, in use).
- Lift and shift applications, either native or containerized, into TEEs with
  little or no modification.
- Allow users to minimize, control, and inspect the makeup of the trusted
  computing base (TCB).
- Simplify re-targeting to other TEE architectures through a plugin
  architecture.
- Publish under a non-restrictive [open-source license](LICENSE).

## Architecture

**Open LibOS** consists of the following components.
- C-runtime based on [musl libc](https://www.musl-libc.org)
- kernel
- kernel-target interface (TCALL)

So far, two target implementations are provided:
- The SGX target (based on the [Open Enclave SDK](https://github.com/openenclave/openenclave))
- The Linux target (for verification on non-SGX platforms)

The minimalist kernel of Open LibOS manages essential computing resources
inside the TEE, such as CPU/threads, memory, files, networks, etc. It handles
most of the syscalls that a normal operating system would handle (with limits).
Many syscalls are handled directly by the kernel while others are delegated to
the target.

![](./arch.png)

# Install or build from source

Binary downloads of the Open LibOS releases can be found on the Releases page
(coming). After downloading the tarball, install it with the following commands:

```
tar xvfz <tarball-name> /opt
export PATH=$PATH:/opt/openlibos/bin
```

To remove a previously installed Open LibOS, simply
`sudo rm -rf /opt/openlibos`.

Open LibOS can be built on an Ubuntu 18.04 machine with or without SGX
capability.

## Install the prerequisites

```
sudo apt update
sudo apt install -y git make libmbedtls-dev docker.io
sudo systemctl start docker && sudo systemctl enable docker && sudo chmod 666 /var/run/docker.sock
```

## Clone, build, and install Open LibOS

```
git clone https://msazure.visualstudio.com/DefaultCollection/One/_git/OpenLibOS
cd OpenLibOS && make
sudo make install
export PATH=$PATH:/opt/openlibos/bin
```

The build process will automatically install all prerequisite for OE SDK first,
including the Intel SGX driver and PSW, and then build the project. Finally,
it installs the build outputs to /opt/openlibos.

Open LibOS can be used to run applications on a non-SGX Ubuntu 18.04 machine
while running with the Linux target (simulation mode). Obviously you need an
SGX-capable machine to try out the SGX target. For that, we recommend either an
[ACC VM](https://aka.ms/accgetstarted) or a bare-metal machine with SGX support.

# Documents

- Getting started with a native C program: [click here](doc/user-getting-started-c.md)
- Getting started with a containerized C++ program: [click here](doc/user-getting-started-docker-c++.md)
- Getting started with a containerized C# program: [click here](doc/user-getting-started-docker-dotnet.md)
- Getting started with a containerized Python program: [click here](doc/user-getting-started-docker-python.md)
- Getting started with a TEE-aware program: [click here](doc/user-getting-started-tee-aware.md)
- Key features of Open LibOS: [click here](doc/key-features.md)
- Open LibOS developer's jump start guide: [click here](doc/dev-jumpstart.md)
- Deep dive into Open LibOS architecture: [coming]
- How to plug a TEE into Open LibOS: [coming]
- Multi-processing and multi-threading in Open LibOS and limitations: [coming]
- Notable unsupported kernel features and syscalls: [coming]
- Signing and packaging applications with Open LibOS: [click here](doc/sign-package.md)
- Release management: [click here](doc/releasing.md)

# Licensing

This project is released under the [MIT License](LICENSE).

# Contributing to Open LibOS

You can contribute to Open LibOS in several ways by:

- contributing code. Please read developer's [jumpstart guide](doc/dev-jumpstart.md) first,
- filing issues with github issues, or
- by simply providing feedback via github issues or email openlibos_notify@microsoft.com.

Please follow the [Code of Conduct (coming)] while participating in the Open LibOS community.
