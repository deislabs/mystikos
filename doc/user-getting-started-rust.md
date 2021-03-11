# Getting started with a native Rust program

Please see [README](../README.md) for how to install Mystikos or build it from source code.

This guide assumes you have Rust installed through [`rustup`](https://rustup.rs) and that you're running on a Linux machine.

You'll need to install the `x86_64-unknown-linux-musl` target which you can by running:

```bash
rustup target add x86_64-unknown-linux-musl
```

# Write the program

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

We need to slightly change how Cargo builds our Rust project from the default. We do this by making some changes in a Cargo config file which we create at `.cargo/config`:

```toml
[target.'cfg(target_env = "musl")']
rustflags = [
    "-C", "linker=myst-gcc", # use `myst-gcc` for linking instead of the system default linker. `myst-gcc` is a wrapper for `musl-gcc` which links to MUSL libc instead of the default glibc.
    "-C", "target-feature=-crt-static", # Don't statically link the musl C runtime. We'll dynamically link to it.
]
```

## Build the program

Compile the project like so:

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

Next we'll move our binary into a new directory we'll create for our application:

```
mkdir appdir
mv ./target/x86_64-unknown-linux-musl/release/myapp appdir
```

`appdir`, is the folder that holds the root file system including the application, the dependent libraries, and
configurations for our execution environment

We're almost done, but not quite. Our binary depends on two dynamic libraries: `musl-libc` and `libgcc` (for unwinding and backtrace support). While the TEE has `musl-libc` on it, it does not have `libgcc`, so we'll need to add it ourselves (and specifically `libgcc_s.so.1`).

Make sure to copy a version of `libgcc` into the `appdir` folder in a subfolder called `lib`. On Ubuntu, `libgcc` can be found at `/lib/x86_64-linux-gnu/libgcc_s.so.1` so you can copy it over like so:

```bash
mkdir appdir/lib
cp /lib/x86_64-linux-gnu/libgcc_s.so.1 appdir/lib
```

This dependency on `libgcc` may go away in the future. Please see [rust#82521](https://github.com/rust-lang/rust/issues/82521) for more details.

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
