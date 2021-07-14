# Getting started with a native C program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

## Write the program

As usual, we use the familiar code:
```
#include <stdio.h>

int main()
{
    printf("Hello world from Mystikos!\n");
    return 0;
}
```
Save it to a folder and call it `helloworld.c`.

## Build the program

Compile `helloworld.c` with `gcc`, and place it under a subdirectory
`appdir`.

```
mkdir -p appdir
myst-gcc -g -o appdir/hello helloworld.c
```

In most cases, we would generate many more files in `appdir`, a folder to hold
the root file system including the application, the dependent libraries, and
configurations. Our hello world program is so simple that it doesn't depend
on any library other than libc. So `appdir` contains
a lonely `hello` executable. That's all we need to run the app inside a TEE.

## Create a CPIO archive

Now we can create a CPIO named `rootfs` out of the folder `appdir` with:
```
myst mkcpio appdir rootfs
```

## Run the program inside an SGX enclave

The command to launch the program inside an SGX enclave is a little bit
long, compared to just `./appdir/hello` on Linux.

```
myst exec-sgx rootfs /hello
```

The command specifies `myst` as the driver, and asks the driver to execute
a program in an SGX enclave in this manner:

1. Load rootfs as the root file system into the enclave
1. Load `/hello` from the file system and execute it.
1. Send parameters following the executable `/hello` to it.
(in this case we have none)

The command specifies myst as the execution environment, and executes a
program in a generic Mystikos SGX enclave for development and debugging
purpose. This execution mode does not capture the identity of the
executing program in the SGX Enclave attestation data, thus is not
suitable for production use.

To run an application with Mystikos in release or production mode, please see
[packaging](./sign-package.md).

## Further readings

If your C program is complicated and requires many dependent libraries,
we recommend that you wrap your application in a container. Please see
[Getting started with a containerized C++ program](./user-getting-started-docker-c++.md)
for details.

