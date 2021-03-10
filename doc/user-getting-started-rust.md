# Getting started with a native Rust program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

Due to an issue in Rust's standard library, it is not currently possible to write Rust programs that use the standard library. See the end of this guide for more information on this issue.

This guide assumes you have Rust installed through [`rustup`](https://rustup.rs) and that you're running on a Linux machine.

You'll need to install the `x86_64-unknown-linux-musl` target which you can by running:

```bash
rustup target add x86_64-unknown-linux-musl
```

## Write the program (no_std)

We'll write a fairly normal `no_std` Rust program. If you've not done `no_std` programming in Rust before, don't worry. While it's not quite as convenient as using the standard library, it's still fairly straight forward.

```bash
cargo new myapp
cd myapp
```

Inside of `src/main.rs` paste the following code:

```rust 
/// We add a few annotations letting Rust know that we're making 
#![no_std] // No standard library
#![no_main] // We'll define our own main symbol

#[no_mangle] // Make sure to expose this function as `main` and not some mangled name
pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
    unsafe {
        // Print using `puts` from `libc`
        libc::puts(b"Hello World!\0".as_ptr() as *const i8);
    }
    0
}

// We're required to specify a panic handler but we'll be aborting
// on panic so no need to do anything here.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
        loop {}
}

// This is a workaround just for musl targets. By default in Rust, musl targets
// statically link libc. This tells Rust to dynamically link libc.
#[link(name = "c")]
extern {}
```

We'll need to add a few things to our `Cargo.toml` manifest:

```toml
# Leave all the things in place up to `dependencies` which you replace with:
[dependencies]
libc = { version = "0.2", default-features = false } # bindings for libc

[profile.release]
panic = "abort" # abort on panic instead of unwinding
lto = true # make our binary smaller and faster by performing link time optimizations
```

Lastly, we need to slightly change how Cargo builds our Rust project. We do this by making some changes in a Cargo config file which we create in our project directory at the path `.cargo/config`:

```toml
[target.'cfg(target_env = "musl")']
rustflags = [
    "-C", "linker=myst-gcc", # use `myst-gcc` for linking. `myst-gcc` is a wrapper for `musl-gcc` which links to MUSL libc instead of the default glibc.
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

In most cases, we would generate many more files in `appdir`, a folder to hold
the root file system including the application, the dependent libraries, and
configurations. Our hello world program is so simple that it doesn't depend
on any library other than MUSL or any configuration. So `appdir` contains
a lonely `myapp` executable. That's all we need to run the app inside a TEE.

## Create a CPIO archive

Now we can create a CPIO named `rootfs` out of the folder `appdir` with:
```
myst mkcpio appdir rootfs
```

## Run the program inside a SGX enclave

The command to launch the program inside an SGX enclave is a little bit
long, compared to just `./appdir/myapp` on Linux.

```
myst exec-sgx rootfs /myapp
```

The command specifies `myst` as the driver, and asks the driver to execute
a program in a SGX enclave in this manner:

1. Load rootfs as the root file system into the enclave
1. Load `/hello` from the file system and execute it.
1. Send parameters following the executable `/hello` to it.
(in this case we have none)

The command specifies myst as the execution environment, and executes a
program in a generic Mystikos SGX enclave for development and debugging
purpose. This execution mode does not capture the identity of the
executing program in the SGX Enclave attestation data, thus is not
suitable for production use.

If you are interested in shortening the command, please see
[packaging](./sign-package.md) as a solution.

## Further readings

If your Rust program is complicated and requires many dependent libraries,
we recommend that you wrap your application in a container. Please see
[Getting started with a containerized C++ program](./user-getting-started-docker-c++.md)
for details.

### Using Rust std library apps

Unfortunately, there is an issue in the Rust std library that makes it usage not currently (as of 10-March-2021) possible. The reason for this is that currently Rust [links to `libgcc` when the C runtime is not statically linked](https://github.com/rust-lang/rust/blob/b36f77012dcbfbcf7d04e29fb9a10c8ead9b3ab1/library/unwind/src/lib.rs#L41) which is what is happening in our case even when we set `panic=abort`. This dependency is not available in the enclave and so the binary fails to run with the following error:

```
Error loading shared library libgcc_s.so.1: No such file or directory (needed by /with_std)
Error relocating /with_std: _Unwind_Resume: symbol not found
Error relocating /with_std: _Unwind_Backtrace: symbol not found
Error relocating /with_std: _Unwind_GetIP: symbol not found
```

You can read more about this issue in [rust#82521](https://github.com/rust-lang/rust/issues/82521).