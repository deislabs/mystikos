# Key Features of Open LibOS

**Disclaimer:** The following key features are subject to change or addition with the
evolvement of Open LibOS.

## Trust based on a single measurement

Before executing in TEE, we have to prove to the TEE that the application,
together with other factors of its execution, such as kernel, C-runtime,
depended libraries, configuration, etc.,  are free from tampering.

In Open LibOS, the C-runtime and the kernel are measured as part of the TEE
image. The measurement also includes the hash of the root file system
on which resides the application, the depended libraries, and the
configuration. In other words, Open LibOS takes all factors that could
influence the execution, and measure them into a single concrete and
verifiable value.

The single measurement could be verified at loading time by the TEE hardware,
therefore protecting the code integrity, or by a relying party during
attestation before secrets are exchanged between the application and the
relying party.

## Single executable package

Of all of things OpenLibOS tries to measure, C-runtime, the kernel, and the
root file system, we could package them into a single executable. The
measurements before and after the packaging remain the same.

We recommend packaging for production usages of Open LibOS as it greatly
simplifies deployment.

## Execution of containerized applications

Open LibOS executes a containerized applications the same way as it executes
a native application, with the extra step of converting a dockerfile into
a root file system.

## Multi-processessing

Open LibOS supports in-enclave process creation with `posix_spawn()`.

A more general support of `fork()` is coming.

## User-kernel isolation

Open LibOS enforces a clean isolation between user space (C-runtime) and
the kernel space as closely as possible to Linux. The only allowed
interactions are:

* entering user space from kernel space, and
* call back into kernel space from user space via standard syscalls

## Kernel-target isolation

Similarly, Open LibOS enforces a clean isolation between target space
and the kernel space. The only allowed interactions are:

* entering kernel space from bootstrapping code running in target, and
* call back into target from kernel via `TCALL` interface.

## TEE-aware applications

Some applications might want to be aware of the TEE they are running inside.
For example, an application might want to behave differently running inside
a TEE vs. outside a TEE. Open LibOS provides a mechanism for them to query
what kind of TEE they are running inside.

Many times, an application running inside the TEE wants to attest to a relying
party with proofs chained to the hardware root of trust, or it wants to
verify the attestation artifacts from an external party. Open LibOS offers
two syscalls to user space, one for generating self-signed certificates rooted
to the TEE, and one for verifying self-signed certificates from another party.

In a more direct way, applications may include header a link a library to
invoke SGX extensions for sealing, attestation, etc..