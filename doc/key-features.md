# Key Features of Mystikos

**Disclaimer:** The following key features are subject to change or addition with the
evolvement of Mystikos.

## Trust based on a single measurement

Before executing in TEE, we have to prove to the TEE that the application,
together with other factors of its execution, such as kernel, C-runtime,
depended libraries, configuration, etc.,  are free from tampering.

Likewise, to establish trust with a relying party during its execution,
the identity of a TEE application, together with other factors of its
execution, needs to be presented to the relying party.

In the current implementation of Mystikos, the C-runtime and the kernel
are measured as part of the TEE application image. The measurement also
includes the hash of the root file system
on which resides the application, the dependent libraries, and the
configuration. In other words, Mystikos takes all factors that could
influence the execution, and measure them into a single concrete and
verifiable value.

The single measurement could be verified at loading time by the TEE hardware,
therefore protecting the code integrity, and by a relying party during
attestation before secrets are exchanged between the application and the
relying party.

Layered Attestation support, where the identity of the application and
the identity of the application's environment, such as the kernel and
the C-runtime, can be attested separately, is under evaluation.

## Single executable package

Of all of things Mystikos tries to measure, C-runtime, the kernel, and the
root file system, we could package them into a single executable. The
measurements before and after the packaging remain the same.

We recommend packaging for production usages of Mystikos as it greatly
simplifies deployment.

## Execution of containerized applications

Mystikos executes a containerized applications the same way as it executes
a native application, with the extra step of converting a dockerfile into
a root file system.

## Multi-processessing

Mystikos supports in-enclave process creation with `posix_spawn()`.

A more general support of `fork()` is coming.

## User-kernel isolation

Mystikos enforces a clean isolation between user space (C-runtime) and
the kernel space as closely as possible to Linux. The only allowed
interactions are:

* entering user space from kernel space, and
* call back into kernel space from user space via standard syscalls

## Kernel-target isolation

Similarly, Mystikos enforces a clean isolation between target space
and the kernel space. The only allowed interactions are:

* entering kernel space from bootstrapping code running in target, and
* call back into target from kernel via `TCALL` interface.

## TEE-aware applications

Some applications might want to be aware of the TEE they are running inside.
For example, an application might want to behave differently running inside
a TEE vs. outside a TEE, or utilize TEE-specific capabilities.
Mystikos provides a mechanism for them to query
what kind of TEE they are running inside.

Quite often, an application running inside the TEE wants to attest to a relying
party with proofs chained to the hardware root of trust, or it wants to
verify the attestation artifacts from an external party. In its current
implementation, Mystikos offers
two syscalls to user space, one for generating self-signed certificates rooted
to the TEE, and one for verifying self-signed certificates from another party.

In a more direct way, applications may include headers and link a library to
invoke SGX extensions for sealing, attestation, etc..

Please refer to
[get started with a TEE aware app](./user-getting-started-tee-aware.md)
for details.