# Mystikos

**Mystikos** is a set of tools for running user applications in a trusted
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

## Architecture

**Mystikos** consists of the following components.
- a C-runtime based on [musl libc](https://musl.libc.org)
- a "lib-os like" kernel
- the kernel-target interface (TCALL)
- a command-line interface
- some related utilities

Today, two target implementations are provided:
- The SGX target (based on the [Open Enclave SDK](https://github.com/openenclave/openenclave))
- The Linux target (for verification on non-SGX platforms)

The minimalist kernel of Mystikos manages essential computing resources
inside the TEE, such as CPU/threads, memory, files, networks, etc. It handles
most of the syscalls that a normal operating system would handle (with
[limits](SYSCALL-LIMITATIONS.md)).  Many syscalls are handled directly by the
kernel while others are delegated to the target.

![](./arch.png)

# Install or build from source

Binary downloads of Mystikos will be made available in the future. 

To build Mystikos from source, follow the [build instructions](BUILDING.md).

**NOTE** that Mystikos can only be built on **Ubuntu 18.04** due to current
limitations in Open Enclave SDK.


# Try it out

Below, you will find a series of guides, increasing in complexity, which
demonstrate various capabilities and use-cases for Mystikos. Go ahead, give it
a try!

- Getting started with a native C program: [click here](doc/user-getting-started-c.md)
- Getting started with a containerized C++ program: [click here](doc/user-getting-started-docker-c++.md)
- Getting started with a containerized C# program: [click here](doc/user-getting-started-docker-dotnet.md)
- Getting started with a containerized Python program: [click here](doc/user-getting-started-docker-python.md)
- Getting started with a TEE-aware program: [click here](doc/user-getting-started-tee-aware.md)
- Key features of Mystikos: [click here](doc/key-features.md)
- Mystikos developer's jump start guide: [click here](doc/dev-jumpstart.md)
- Deep dive into Mystikos architecture: [coming]
- How to plug a TEE into Mystikos: [coming]
- Multi-processing and multi-threading in Mystikos and limitations: [coming]

# Additional Documentation

Here are some additional documents, which we should organize better in the future.

- Notable unsupported kernel features and syscalls: [coming]
- Signing and packaging applications with Mystikos: [click here](doc/sign-package.md)
- Release management: [click here](doc/releasing.md)

# Licensing

This project is released under the [MIT License](LICENSE).

# Reporting a Vulnerability

Security issues and bugs should be reported privately via email to the
[Microsoft Security Response Center](https://www.microsoft.com/en-us/msrc)
(MSRC) at secure@microsoft.com. You should receive a response within 24 hours.
If for some reason you do not, please follow up via email to ensure we received
your original message.

# Contributing to Mystikos

See the [Contributing Guide](CONTRIBUTING.md).

# Code of Conduct

This project has adopted the
[Microsoft Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
All participants are expected to abide by these basic tenets to ensure that the
community is a welcoming place for everyone.
