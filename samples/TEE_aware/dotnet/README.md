# TEE-aware program for Mystikos in .NET

This sample guides users to create TEE-aware applications, which are
essential to many confidential computing scenarios.

It is recommended that you understand how to use EXT2 file system and how applications can be packaged
Mystkos before proceeding with this sample. Please refer to the README for the helloworld sample
to obtain the necessary information.

To understand the differences between running an application inside Mystikos vs running it in outside,
please refer to the [gencreds sample](../gencreds/README.md)

## Functionality

This .NET sample opens the certificate, the private key and report files. It then converts private key from pem to der if necessary.
It can then use these credentials if necessary.

## Getting started with .NET

A .cs file and a csproj are located in `TEEAware` directory.
Dockerfile builds the .csproj.

## Transform a Dockerfile into a root file system

`Dockerfile` sets up all the prerequsites to use the .net SDK and build the .csproj file.
`myst-appbuilder` is used to convert the Dockerfile into a directory containing all the files needed to run this application in Mystikos.
```
myst-appbuilder -v -d Dockerfile
```

## Configuration Parameters

These are the configuration parameters used. The memory needed to run this .NET application is much larger than the helloworld application.
```json
{
    "Debug": 1,
     
    "ProductID": 1,
    "SecurityVersion": 1,    
    // The heap size of the user application. Increase this setting if your app experienced OOM.
    "MemorySize": "1g",
    // The path to the entry point application in rootfs
    "ApplicationPath": "/app/TEEAware",
    // The parameters to the entry point application
    "ApplicationParameters": [],
    // Whether we allow "ApplicationParameters" to be overridden by command line options of "myst exec"
    "HostApplicationParameters": false,
    // The environment variables accessible inside the enclave.
    "EnvironmentVariables": ["COMPlus_EnableDiagnostics=0", "MYST_WANT_TEE_CREDENTIALS=CERT_PEMKEY_REPORT"],
    "UnhandledSyscallEnosys": false
}
```
To learn more about configuration, please refer to related [documentation](../../../doc/sign-package.md).

High level languages like C# don't have direct access to syscalls as
C/C++ do. Therefore, we introduce the environment variable
`MYST_WANT_TEE_CREDENTIALS`, which when specified in `config.json`, instructs
Mystikos to generate desired credentials and save them on the file system
for applications to make use of.


Note that the last line `MYST_WANT_TEE_CREDENTIALS=CERT_PEMKEY_REPORT` tells
Mystikos to generate three files for the application:
1. a self-signed x509
certificate with an ephemeral RSA public key
1. a private RSA key (in PEM format) that is paired with the public key
1. a TEE-backed report that attests to the public key (by including the
hash of the public key in the signed report)

When Mystikos starts up, these files are stored in /tmp for the Mystikos file system.

`
string certFile = "/tmp/myst.crt";
string pkeyFile = "/tmp/myst.key";
string reportFile = "/tmp/myst.report";
`
The application can then load these credentials. 

To learn more about writing TEE aware applications, please read the [TEE aware application documentation](../../../doc/user-getting-started-tee-aware.md).


## Running the sample

To run the sample in package mode, use `make run`.

To run the sample using `myst exec-sgx`, use `make runexec`. Note that the `myst-exec` command takes the application configuration as a parameter
```
@myst exec-sgx $(OPTS) ext2rootfs /app/TEEAware --app-config-path config.json
```
This is because additional application configuration such as the the application parameters and environmental variables are supplied by config.json.
