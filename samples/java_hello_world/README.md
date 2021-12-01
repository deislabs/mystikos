# Java sample 

This sample demonstrates how a java application can be run in Mystikos

It is recommended that you understand how to use EXT2 file system and how applications can be packaged
Mystkos before proceeding with this sample. Please refer to the README for the helloworld sample
to obtain the necessary information.

## Transform a Dockerfile into a root file system
`Dockerfile` imports from openjdk:13-alpine.  The `javac` command is used to compile `helloworld.java` into class files that run on a JVM.
`myst-appbuilder` is used to convert the Dockerfile into a directory containing all the files needed to run this application in Mystikos.
```
myst-appbuilder -v -d Dockerfile
```

After this, the `appdir` generated can be converted into a cpio archive using `myst mkcpio` or an EXT2 file system using `myst mkext2`that can be loaded into Mystikos.
In this sample, we use an EXT2 file system.

## Functionality 

This sample prints `hello world` from a java application. The source code is contained in `helloworld.java`.

### Running the sample

To run the sample in package mode, use `make run`.

To run the sample using `myst exec-sgx`, use `make runexec`.

### Configuration Parameters

The configuration used in this sample is very similar to that in the [C helloworld sample](../helloworld/README.md). Please refer to the helloworld sample for more details.
It does use more memory than the helloworld sample(which is written in C). This is in order to run the JVM.
After mounting the root file system, Mystikos invokes `/opt/openjdk-13/bin/java` with `ApplicationParameters` specifying `helloworld`.
```
{
    "Debug": 1,
    "ProductID": 1,
    "SecurityVersion": 1,
    "UserMemSize": "4096m",
    "CurrentWorkingDirectory": "/app",
    "ApplicationPath": "/opt/openjdk-13/bin/java",
    "ApplicationParameters": ["helloworld"]
}
```
To learn more about configuration, please refer to related [documentation](../../doc/sign-package.md).
