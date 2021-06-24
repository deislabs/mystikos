# Mystikos Developer's Jumpstart Guide

This document contains an overview of the code layout and development model, to help a new developer get started writing code for the project. It's a good read before your first PR.

## Browsing the source code

Please see [README](../README.md) for how to obtain the source code.

Under the root directory, we have:
*  `third_party/musl/crt` folder that implements the libc library, using MUSL
as a submodule;
* `kernel` that implements the kernel library;  and
* `target` that implement a few targets we support so far.
* Specifically for the SGX target, folder `third_party/openenclave` provides
enclave related functions with Open Enclave SDK as a submodule. We use a
feature branch from the OE SDK repo.

Also under the root directory:

* The `tests` folder contains test cases we run for CI/CD pipelines.
* The `solutions` folder contains sophisticated applications we can run with
Mystikos. They are also covered by the CI/CD pipeline.
* The `samples` folder contains test cases for evolving features which are
not stable enough to be moved into `tests`.
* The `scripts` folder contains several helper scripts for using Mystikos
or integrating with the pipeline.
* The `tools` folder contains a SGX enclave that bootstraps Mystikos, as
well as the host launcher.


## Trying it out

Please see [README](../README.md) for how to install the pre-requisite packages
and build the source code.

The following instructions assume Mystikos is cloned to `$HOME/Mystikos`,
referred to as `project root` hereafter.

1. The build process creates a `build` folder under the project root, which
consists of the following artifacts:
    * bin: the executables of Mystikos, including:
        * the main executable `myst`
        * the debugger `myst-gdb`
    * musl, including:
        * musl-gcc, which is used to compile the C-runtime, kernel and target
        libraries
    * lib, including:
        * libmystcrt.so, the output from building `third_party/musl/crt`
        * libmystkernel.so, the output from building `kernel`
        * mysttarget*.a, the output from building target libraries
        * openenclave/mystenc.so, the output from building `tools/myst/enc`
    * openenclave, including the outputs from building OE SDK.
    * crt-musl: the source code of C-runtime, after patching MUSL
1. Run a simple application built with musl-gcc
    ```
    cd Mystikos/tests/hello
    make
    make tests
    ```
    In the 2nd step `make`, we create a temporary folder `appdir`, compile
    `hello.c` with `musl-gcc`, and place the output executable under
    `appdir/bin/hello`, finally we create a CPIO archive out of `appdir`.

    In the 3rd step `make tests`, we launch `myst`, giving it the CPIO
    archive, the command to run (`/bin/hello` in this case), and
    finally, the command line arguments, e.g., "red", "green", and "blue".
    With this step, we should see the following outputs:
    ```
    Hello world!
    I received: argv[0]={/bin/hello}, argv[1]={red}, argv[2]={green}, argv[3]={blue}
    ```
1. Run an existing application included in Alpine Linux

    [Alpine Linux](https://alpinelinux.org/) is a Linux distribution that uses
    MUSL as its libc implementation. Since Mystikos provides a libc
    interface based on MUSL, many applications included in Alpine Linux could
    be run with Mystikos without modification.
    ```
    cd Mystikos/tests/alpine
    make
    make tests
    ```
    In the 2nd step, we download and extract a version of `alpine-minirootfs`,
    put it under `appdir`, and create a CPIO archive out of `appdir`.

    In the 3rd step, we execute command `ls` on the CPIO archive with `myst`.

## Advanced experiments

1.  Run an application built with a docker container based on Alpine Linux with
a default Dockerfile

    When an application depends on 3rd party libraries, we should use docker
    containers that based on Alpine Linux to install the necessary packages
    and then build the application. We provide a default dockerfile
    `alpine/Dockerfile` under the project root for building some
    of our tests/samples.
    ```
    cd Mystikos/samples/goodbye
    make
    make run
    ```
    In the 2nd step, we launch a docker container with a pre-built image out
    of `alpine/Dockerfile`, and compile the application `goodbye.c`.
    Again, the build outputs are placed under `appdir` which is converted into
    a CPIO archive.

1. Run an application built with a docker container based on Alpine Linux with a
customized Dockerfile

    The default dockerfile `alpine/Dockerfile` includes packages such
    as `build-base`, `mbedtls-dev`, and `curl`. For applications that depend on
    libraries not included in the default dockerfile, we need to provide a
    customized Dockerfile.
    ```
    cd Mystikos/solutions/attested_tls
    make run
    ```
    During `make run`, we use a customized dockerfile
    `solutions/attested_tls/Dockerfile` to create a docker image, and then
    launch it to build the application. We use the script `appbuilder` to
    automate the process.

## Debugging

Mystikos currently can be run on two targets, SGX Target or Linux Target. When run on SGX Target, we have four ELF partitions, and on the Linux Target we have three ELF partitions (as shown in Fig 1). It is possible that the different ELF regions have the same function symbol repeated in them, eg: having two `main()` functions; in this case, if you set a breakpoint on `main`, GDB will consider both of them as breakpoints.

![Mystikos ELF regions](myst-elf-regions.jpg) Fig 1

C Call -> Call from the user application to the C-Runtime

Syscall -> Calls into the kernel

T Call -> Target call/calls into the target

O Call -> Calls into the host (untrusted environment)

1. For most applications under `tests`, we can launch the debugger with
command `make tests GDB=1`. For example:
    ```
    cd Mystikos/tests/hello
    make && make tests GDB=1
    ```
    For applications that are run in [package mode](../solutions/dotnet/Makefile#23), ensure that the field `"Debug":1` is set in the `config.json` file, and the debugger can be launched using the run command:
    
    ```
    myst-gdb --args myst/bin/<appname> <opts>
    ```

1. Once inside the gdb window, we can set two breakpoints to examine the
events during booting Mystikos and launching user applications.
    ```
    break main
    break myst_enter_crt
    run
    ```

1. The first breakpoint should be hit at the `main` function in
`Mystikos/tools/myst/host/host.c`. This is the host launcher for the
bootstrapping enclave.

1. Enter `continue` command to gdb, the second breakpoint should be hit
at the `myst_enter_crt` function in `Mystikos/crt/enter.c`.

1. The `where` command to gdb reveals that we have gone through the
following events to reach the point of starting C-runtime (CRT):

    * **myst_enter_ecall**, where we cross the boundary between the
    host launcher and the bootstrapping enclave.
    * **myst_enter_kernel**, where we cross the boundary between
    the bootstrapping enclave and the kernel.
    * **myst_enter_crt**, where we cross the boundary between the
    kernel and CRT

1. Enter `continue` command to gdb, the third breakpoint should be hit
at the `main` function in the user application.
1. Now in the GDB window, set a breakpoint to observe how Mystikos
handles syscalls.
    ```
    break myst_syscall
    continue
    where
    ```
1. Experiment with more gdb commands and breakpoints.


