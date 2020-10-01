# Open LibOS Getting Started Guide

This document describes how to use the Open LibOS, from building the project to packaging your application through to executing it.

First we will explain a little about what Open LibOS does, followed by how to build the application yourself, along with installing the tools.

Then how to use the tools to package up your executable within the Open LibOS environment, followed by how to run and debug your executable.

Note: Open LibOS is currently only tested on Ubuntu 18.04.
Note: Currently the Open LibOS codebase is in a private GitHub repository.

---

## Introduction to Open LibOS

Open LibOS is a set of binaries and libraries that allows an application to be run under different environments.

The primary environment is currently to run an application on in an Intel SGX Enclave. This is a protected environment that protects your run-time data from the rest of the operating system. If the application is being run within a virtual machine then it also protects the run-time data from the host operating system as well. Run-time data in this case could be a stream of data being fed to the application through a secure TLS channel where machine learning applications can process the data and protect the data from other applications running within the same operating system, guest operating system, or host operating system.

Another environment exists to run the same application outside the SGX enclave, and targeted against the operating system directly. This is a great environment for checking if your application is having problems within an SGX enclave only, or is having problems for some other reason.

Along with the runtime comes a debugger extension to allow developers to debug their application when run within the secure enclave, but this is only available in debug mode which allows the application to run in the secure enclave but the data is not secure and should never be used in production environments.

Open LibOS is made up of a number of parts, from the tools needed to prepare your application to be run, to the components needed to run your application within Open LibOS, to the debugging tools.

---

## Building and installing Open LibOS

Currently Open LibOS can only be installed after being built from source. This section describes the process for pulling down the source and how to build and install it.

First the sources need to be pulled down to your Ubuntu machine and built.

Grabbing the source through `git clone` is done as follows:

```bash
git clone --recurse-submodules https://github.com/mikbras/oe-libos.git
```

***TODO*** What are the prerequisites for building Open LibOS?

Change into the directory and build the project:

```bash
make
```

The binaries are built into the `build` directory.

You can run this to get the initial usage help of Open LibOS:

```bash
./build/bin/libos
```

Open LibOS can be run directly from this directory, or it can be installed.

Install Open LibOS by running the following command:

```bash
sudo make install
```

This will install into the default installation directory `/opt/openlibos`. If you want you can override the `LIBOS_PREFIX` environment variable before building and install it wherever you want, for instance you may want to install under your user home directory. Installing to the default location requires elevated permissions via `sudo`, but in the case of installing under your home directory the `sudo` is not needed. You just need to set your path the the `bin` directory under where you install to.

---

## Preparing your application to run under Open LibOS

For your application to be run within Open LibOS you need to package up the executable and all associated shared libraries and configuration within into a directory that can be consumed by the packaging process.

Currently your application will need to be built against the MUSL C-runtime, rather than the GLIBC runtime.

Once built you will need to place it under a directory that will become the root filesystem for your application when it is run. Only files placed in this directory will be available within the root filesystem. It is also important to note that although this will become a read/write filesystem during executable, this filesystem will not be persisted for the next execution and will be started with the same initial filesystem each time.

What you may have for your project is this under your source directory:

```bash
$ ls .
Makefile
source.c
```

As before you will build and place all relevant files into a directory that may result in a directory structure like this:

```bash
$ ls ./appdir
myapp
```

If you have an executable with different shared libraries and configuration you may end up mimicking the Linux filesystem structure. This `appdir` will be important for the next step.

---

## Packaging your application in Open LibOS

In order to prepare your application to run under Open LibOS you need to package your application directory `appdir` using the Open LibOS tools to produce a singleOpenLibOS executable that will run your executable within the target environment, be it an SGX enclave or the none protected operating system.

For preparing to run under the SGX enclave you will need a couple of different things along with your existing `appdir`.

---

### Signing certificate for SGX enclave packaging

When an executable is run within an SGX enclave it is usually signed with a signing certificate that is controlled by the application developer. This signing certificate needs to be kept very secure as this helps to form part of the identity of the SGX enclave and can be used as part of the attestation for the application to prove it is running in an SGX enclave and the application is trustworthy using this key.

One way to get a key is to use OpenSSL with a command like this:

```bash
openssl genrsa -out private.pem -3 3072
```

For a production environment a self signed key is not sufficient and will need a trusted signing authority that can be validated.

This signing certificate will then be used later in the preparation of your application package.

---

### Application configuration for SGX enclave packaging

A Open LibOS package needs configuration to control certain run-time environmental settings as well as settings that control how the application reads environmental data from the insecure host environment.

Included is a sample JSON configuration where the elements will be described next, and will be the `config.json` file that is used in the packaging.

```json
{
    "version": "0.1",

    "Debug": 1,
    "KernelMemSize": "4m",
    "StackMemSize": "256k",
    "NumUserThreads": 2,
    "ProductID": 1,
    "SecurityVersion": 1,

    "UserMemSize": "40m",
    "ApplicationPath": "/bin/hello",
    "ApplicationParameters": [
        "Enclave-red", "Enclave-blue",
        "Enclave-green", "Enclave-yellow",
        "Enclave-pink"
    ],
    "HostApplicationParameters": true,
    "EnvironmentVariables": [
        "ENC-ENVP-1=Enclave_envp_1",
        "ENC-ENVP-2=Enclave_envp_1"
    ],
    "HostEnvironmentVariables": ["TESTNAME"]
}
```

---

First we have the global settings for Open LibOS.

---

Setting | Description
-|-
version | LibOS configuration version number. If the schema version is changed within Open LibOS this version ties this configuration to a specific schema version

---

Next we have settings specific to configuring the SGX enclave itself.

---

Setting | Description
-|-
Debug | Enable debugging within the SGX enclave, turn off for release builds
KernelMemSize | The amount of memory for the Open LibOS kernel, in this case 4 MB
StackMemSize | Stack size for kernel
NumUserThreads | Number of threads allowed within the enclave. If more threads are created than this number thread creation will fail
ProductID | The product ID of your application. This is an integer value
SecurityVersion | Security version of your application. This is an integer value.

---

Finally we have the Open LibOS application specific settings.

---

Settings | Description
-|-
UserMemSize | Amount of user memory your application needs to run. Try not to make this just a very large number as the larger this number needs to be the slower load time will be. In this case 40 MB. Value can be bytes (just a number), Kilobytes (number with k after), or megabytes (number with m after)
ApplicationPath | The executable path relative to the root of your appdir. This executable name is used to determine the final application name once packaged.
ApplicationParameters | Enclave defined application parameters if HostApplicationParameters is set to false.
HostApplicationParameters | This parameter specifies if application parameters can be specified on the command line or not. If true they are and the command line arguments are used instead of the ApplicationParameters list of parameters
EnvironmentVariables | Enclave defined environment variables
HostEnvironmentVariables | A list of environment variables that can be imported from the insecure host

---

### Packaging your application for SGX enclave packaging

Packaging of the executable requires all the things that have now been created:

* executable and supporting files in `appdir`
* signing certificate
* configuration

With these three things a package can be created with the following command:

```bash
libos package-sgx ./appdir private.pem config.json
```

During the packaging process all the Open LibOS executables and shared libraries are pulled together with the application directory and configuration and signed with the signing certificate. All enclave resident pieces of Open LibOS and the `appdir` are all measured during the signing process and this measurement is verified while the SGX enclave is created. If there is a mismatch then the loading will fail.

The results of this command is a single executable with the same name as specified in the configuration.

Execution is as simple as running the executable:

```bash
./myapp
```

If your configuration allows command line parameters from the insecure host then they can also be added to this command as well:

```bash
./myapp arg1 arg2
```

If the host arguments are not allowed to be passed then any specified within the configuration will be added when Open LibOS transitions to the secure enclave.

If any host environment variables are configured as available within the SGX enclave then this command will pass them though. Enclave specific environment variables will be added once Open LibOS transfers control to the enclave.

---
