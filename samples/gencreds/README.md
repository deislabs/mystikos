# gencreds -  a TEE-aware program for Mystikos

This sample guides users to create TEE-aware applications, which are
essential to many confidential computing scenarios.

It is recommended that you understand how to use EXT2 file system and how applications can be packaged
Mystkos before proceeding with this sample. Please refer to the README for the helloworld sample
to obtain the necessary information.


## Set up pre-requisites

It is essential for this program to be able to find Mystikos header files installed as part of the Mystikos package.
To ensure that the Makefile can find the headers, export a variable `MYSTIKOS_INSTALL_DIR` and set it to the path of
the Mystikos installation on the system. As an example, if Mystikos is installed on /opt/mystikos, then issue
 the following command on the command prompt:

```cmd

export MYSTIKOS_INSTALL_DIR=/opt/mystikos.

```

## The problem statement

Why would an application want to be aware of the TEE it's running within? Two
possible requirements are:

* In an **isolated confidential computing** scenario, the application should
  behave differently based on whether it's running
  inside a TEE or not, and, if it is, which types of TEE;
* In a **collaborated confidential computing** scenario, the application wants
  to get help from the TEE, and gain trust to obtain secrets from an external
  party which enforces a policy such as only releasing keys to applications
  running inside a TEE with certain identities.

Why is **collaborated confidential computing** so important?
Imagine a doomsday scenario when the digital world has fallen: all routers/NICs
on the internet and all operating systems become untrustworthy, the
**collaborated confidential computing** would enable a group of
applications, serving as `safe harbors`, to collaborate and fight against
the malicious world.

## Mystikos solution

Mystikos provides two environment variables, `MYST_TARGET` and
`MYST_WANT_TEE_CREDENTIALS`, for TEE-aware applications.

`MYST_TARGET` is read only, and applications can query the variable to
find out whether it is running outside or inside a TEE, and, when it's
running inside a TEE, which specific TEE platform it is.

When applications set `MYST_WANT_TEE_CREDENTIALS` to `CERT_PEMKEY`, the Mystikos
runtime, as part of the booting process, will generate:

* a self-signed TLS certificate with the root of trust from the
TEE; and
* an ephemeral private key corresponding to the public key embedded
in the certificate.

Both credentials are then saved to a fixed location in the file system.
Note the private key is exported in PEM format.
With both the certificate and the private key, the application can establish
an attested TLS channel with a peer, as long as the peer could perform
verification on the certificate and relate it to the root of trust from
the TEE. Now both parties can exchange secrets without the fear of
eavesdropping from malicious actors on the internet.

Furthermore, Mystikos provides two system calls, one for generating the above
mentioned certificate and private key, one for verifying the certificate,
for languages that support the direct invocation of syscalls, such as C/C++.
These syscalls give application the flexibility to generate or verify as
many TLS certificates as possible at any time, without relying on
`MYST_WANT_TEE_CREDENTIALS`.

For applications written in high level languages which allow no direct
syscalls, FFI can be used to call into a native library that exposes such
system calls.


## Write a program that behaves differently for TEE and non-TEE

This example shows how to write a program that potentially performs secret
operations only when running inside a TEE.

Here is a code snippet inside `gencreds.c`.

```c
    if ( !target )
    {
       printf("****I am in unknown environment, returning\n");
       return 0;
    }
    if (strcmp(target, "sgx") != 0)
    {
        printf("****I am in non-TEE, returning\n");\
        return 0;
    }
    else
    {
        printf("****I am in an SGX TEE, I will proceed to generate and verify TEE credentials\n");\
```
In the Makefile, the make run command runs the program outside of Mystikos and inside Mystikos
```
	echo "Running application outside a TEE."
	appdir/bin/gencreds
	echo "Running Mystikos packaged application inside an SGX TEE."
	./myst/bin/gencreds
```


## Run the program


Issue the `make run` command.

Here is the output:
```
Running application outside a TEE.
appdir/bin/gencreds
***I am in unknown environment, returning
echo "Running Mystikos packaged application inside an SGX TEE."
Running Mystikos packaged application inside an SGX TEE.
./myst/bin/gencreds
****I am in an SGX TEE, I will proceed to generate and verify TEE credentials
```

## Generating and verifying self-signed certificates programmatically

This section shows how to generate a TLS certificate and verify it using
system calls with C/C++. This is not interesting by itself because there
is no peers to establish trust with. For a peer-to-peer trusted channel
example, please check
[solutions attested_tls](https://github.com/deislabs/mystikos/tree/main/solutions/attested_tls).

A self-signed certificates generated by Mystikos includes:

* A public key for subsequent encrypted communications, and
* An attestation report containing:
    * The proof that the application is running in a specific TEE;
    * The application's identity; and
    * The hash of the communication public key.

When running with Mystikos, an application verifies the self-signed certificate
from a peer by issuing a syscall to Mystikos that:

1. extracts the public key and the attestation report;
1. checks if the attestation report is genuinely generated by a TEE;
1. checks if the hash of the public key matches the hash value inside
the attestation report;
1. checks if the application identity is expected. See `_verifier`
function below as an example.

```c

int _verifier(myst_tee_identity_t* identity, void* ptr)
{
    // Expected Product ID: {1}
    const uint8_t PRODID[MYST_PRODUCT_ID_SIZE] = {1};
    // Expected security version: 1
    const int SVN = 1;

    // Returning 0 means pass.
    // We can easily expand this to more sophicated checks
    // based on unique_id, signer_id, etc.
    return memcmp(identity->product_id, PRODID, MYST_PRODUCT_ID_SIZE) ||
           identity->security_version != SVN;
}

int main()
{
    ...

    ret = syscall(SYS_myst_gen_creds, &cert, &cert_size, &pkey, &pkey_size);
    assert(ret == 0);
    printf("Generated a self-signed certificate and a private key\n");

    ret = syscall(SYS_myst_verify_cert, cert, cert_size, _verifier, NULL);
    assert(ret == 0);
    printf("Verified the self-signed certificate\n");

    ret = syscall(SYS_myst_free_creds, cert, cert_size, pkey, pkey_size);
    assert(ret == 0);
    ...
}

```

The application is free to provide `NULL` for the third parameter of
`SYS_myst_verify_cert`. In that case, Mystikos would accept any
application running inside a TEE with no regard to the application identity.

If the application does want to reject/approve based on an app identity, it
must include `myst/tee.h`, which defines a function similar to `_verifier`,
and pass it to the syscall `SYS_myst_verify_cert`.

Issue the `make run` command in order to generate and verify the certificate.

