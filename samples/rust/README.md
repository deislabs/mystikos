# RUST sample 

This sample demonstrates how a rust application can be run in Mystikos

It is recommended that you understand how to use EXT2 file system and how applications can be packaged
Mystkos before proceeding with this sample. Please refer to the README for the helloworld sample
to obtain the necessary information.

## Transform a Dockerfile into a root file system
`Dockerfile` imports from a base RUST image and builds `src/hello` with `Cargo`.
`myst-appbuilder` is used to convert the Dockerfile into a directory containing all the files needed to run this application in Mystikos.
```
myst-appbuilder -v -d Dockerfile
```

After this, the `appdir` generated can be converted into a cpio archive using `myst mkcpio` or an EXT2 file system using `myst mkext2`that can be loaded into Mystikos.
In this sample, we use an EXT2 file system.

## Functionality 

This sample prints `hello world` from a RUST application. The source code is contained in `/hello/src/main.rs`.

### Running the sample

To run the sample in package mode, use `make run`.

To run the sample using `myst exec-sgx`, use `make runexec`.

### Configuration parameters
The configuration used in this sample is very similar to that in the helloworld sample. Please refer to the helloworld sample for more details.
```
{
    // Mystikos configuration version number
    "version": "0.1",

    // OpenEnclave specific values
    "Debug": 1,
    "ProductID": 1,
    "SecurityVersion": 1,

    // Mystikos specific values
    "HostApplicationParameters": true,
    "MemorySize": "40m",
    "ApplicationPath": "/app/hello"
}
```
To learn more about configuration, please refer to related [documentation](../../doc/sign-package.md).