- PR Pipeline: [![Build Status](https://openenclave.visualstudio.com/ACC-Services/_apis/build/status/oe-libos-master-pipeline?branchName=master)](https://openenclave.visualstudio.com/ACC-Services/_build/latest?definitionId=70&branchName=master)
- Nightly Pipeline: [![Build Status](https://openenclave.visualstudio.com/ACC-Services/_apis/build/status/oe-libos-nightly-pipeline?branchName=refs%2Fpull%2F84%2Fmerge)](https://openenclave.visualstudio.com/ACC-Services/_build/latest?definitionId=83&branchName=refs%2Fpull%2F84%2Fmerge)

# Open LibOS

Open Library Operating System, or Open LibOS for short.

## Introduction

Run your applications inside a TEE. Currently support running in an SGX enclave, or in an unprotected environment within the operating system.

Open LibOS is not tied to a specific TEE, and instead is architected to allow different TEEs (or targets) to be plugged in against our Open LibOS kernel.

The Open LibOS kernel Handles most of the operating system primitives that a normal operating system would handle (with limits), and certain operations (like networking) are delegated to the actual operating outside the TEE itself.

Your application needs to be linked against the libc shared libraries rather than statically linking as Open LibOS needs to hook certain functions within that library so calls get routed through the Open LibOS kernel. MUSL is supported, with GLIBC support being implemented.

## Documents

User getting started guide: [click here](doc/user-getting-started.MD)

Release management: [click here](doc/releasing.md)
