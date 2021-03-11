# Getting started with a native Rust program

Please see [README](../README.md) for how to install Mystikos or build it from source code.

This guide assumes you have Rust and cargo installed (which you can do using [`rustup`](https://rustup.rs)) and that you're running on a Linux machine.

# Write the program

We can run normal Rust binaries inside the TEE.

First, we create a new project using cargo:

```bash
cargo new myapp
cd myapp
```

Inside of `src/main.rs` paste the following code:

```rust
fn main() {
    println!("Hello world!");
}
```

## Build the program

Compile the project like so:

```bash
cargo build --release 
```

Next we'll move our binary into a new directory we'll create for our application:

```
mkdir appdir
mv ./target/release/myapp appdir
```

`appdir`, is the folder that holds the root file system including the application, the dependent libraries, and
configurations for our execution environment

We're almost done, but not quite. Our binary depends on several dynamic libraries, two of which are not present in the execution environment: `libgcc` (for unwinding and backtrace support) and `ld`. We'll need to add it ourselves (and specifically `libgcc_s.so.1` and `ld-linux-x86-64.so.2`).

Make sure to copy version of these missing dynamic libraries into the `appdir` folder in a subfolder called `lib`. On Ubuntu, they can be found inside `/lib/x86_64-linux-gnu` so you can copy it over like so:

```bash
mkdir appdir/lib
cp /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 appdir/lib
```

## Create a CPIO archive

Now we can create a CPIO named `rootfs` out of the folder `appdir` with:
```
myst mkcpio appdir rootfs
```

## Run the program inside a SGX enclave

The command to launch the program inside an SGX enclave is a little bit long, compared to just `./appdir/myapp` on Linux.

```
myst exec-sgx rootfs /myapp
```

The command specifies `myst` as the driver, and asks the driver to execute a program in a SGX enclave in this manner:

1. Load rootfs as the root file system into the enclave
1. Load `/myapp` from the file system and execute it.
1. Send parameters following the executable `/myapp` to it.
(in this case we have none)

The command specifies myst as the execution environment, and executes a program in a generic Mystikos SGX enclave for development and debugging purpose. This execution mode does not capture the identity of the executing program in the SGX Enclave attestation data, thus is not suitable for production use.

If you are interested in shortening the command, please see [packaging](./sign-package.md) as a solution.

## Further readings

If your Rust program is complicated and requires many dependent libraries, we recommend that you wrap your application in a container. Please see [Getting started with a containerized C++ program](./user-getting-started-docker-c++.md) for details.
