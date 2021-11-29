# Hello World Sample

This is a sample which demonstrates how to get started on development in Mystikos.
The application run in this sample is a simple C application.
A Mystikos application can be contained in a CPIO archive, an EXT2 file system or in a Mystikos Package.
To learn more about these three mechanisms, please read through below.
It is recommended that you understand the [developer workflow](../doc/user-getting-started.md#app-development-workflow) for Mystikos.


There are two directories in this sample

## OPTION1 cpioroots- Build CPIO Archive

### Build a CPIO archive and run using myst-exec
1. `hello.c` is compiled with gcc. The resulting application is placed in `appdir`.
```
   gcc -fPIC -o appdir/bin/hello hello.c
```
2. A cpio archive is constructed from `appdir`. 
```
   myst mkcpio appdir cpiorootfs
```
3. `myst exec-sgx` is used to run the application contained inside the cpio archive.
During execution, the cpio archive is mounted as the root file system.
```
    msyt exec-sgx cpiorootfs /bin/hello red green blue
```
4. To run the sample in CPIO Archive mode, from the command prompt, use the following make command.

This builds `appdir`, `cpiorootfs` and executes the application contained within `cpiorootfs`.
```
    make runexec
```
### Build and run a self contained package
1. An `appdir` is generated as above
1. A signing key is generated using

```
 openssl genrsa -out package.pem -3 3072
 ```
  To learn more about signing, please see  [packaging and signing documentation](../../doc/sign-package.md)

3. A package is generated using the `myst package` command
```
   myst package-sgx appdir package.pem config.json
```
 This creates a `myst` directory and places the application under it.

 It is important to note that a configuration file is provided to `myst package`. 
 To see more information regarding configuration, please refer to [Configuration Parameters](#configuration-parameters)

4. At this point the application is self contained. To run it, just run the application under the `myst` directory.
```
./myst/bin/hello red green blue
```

5. To run the sample in package mode, from the command prompt, use the following command.

This builds `appdir`, `package`, the signed package and executes the application contained within the package
```
    make run

```


## OPTION2 Build an EXT2 filesystem

### Build an EXT2 file system and run using myst-exec
This is an option for developers to use instead of using a CPIO archive.
An EXT2 file system is integrity protected and can be signed.
To learn more about the EXT2 file system, please see [Running Simple Applications](../../doc/running-simple-app.md#ext2).
It also supports [signing](../../doc/sign-package.md,) and
[encryption of the entire file system](../../doc/running-simple-app.md#creating-an-encrypted-ext2-image)

1. Just as in the `CPIO Archive Mode`, `hello.c` is compiled with gcc. The resulting application is placed in `appdir`.
```
   gcc -o appdir/bin/hello hello.c
```
2. A EXT2 File System is constructed from `appdir`. 
```
   myst mkext2 appdir ext2rootfs
```

The following command dumps the merkel tree for the integrity protected EXT2 file system.
``` 
    myst fssig --roothash ext2rootfs > roothash
```
Dumping the merkel tree is *optional*.

3. `myst exec-sgx` is used to run the application contained inside EXT2  File System.
```
   myst exec-sgx --roothash=roothash ext2rootfs /bin/hello red green blue
```
Note that the roothash parameter is *optional*. It provides msyt exec-sgx a way to ensure that the ext2rootfs has not been tampered with.

4. To run the sample in EXT2 file system mode, from the command prompt, use the following make command.
This builds `appdir`, `ext2rootfs` and executes the application contained within `ext2rootfs`.
```
    make runexec
   ```

### Build a signed package and run the application in a self contained package
1. The EXT2 root file system is created as demonstrated above.

2. A signing key is generated using

```
 openssl genrsa -out package.pem -3 3072
 ```
  To learn more about signing, please see  [packaging and signing documentation](../../doc/sign-package.md)

3. A package is generated using the `myst package` command
```
   myst package-sgx -roothash=roothash appdir package.pem config.json
```
 This creates a `myst` directory and places the application under it.
 
 Using the `roothash` param is *optional*. When used, it ensures that the filesystem's integrity is verfied against the Merkel tree described by `roothash`.

 It is important to note that a configuration file is provided to `myst package`. 
 To see more information regarding configuration, please refer to [Application configuration](../../doc/sign-package.md#application-configuration-for-sgx-enclave-packaging).


4. At this point the application is self contained. To run it, just run the application under the `myst` directory.
```
./myst/bin/hello red green blue
```

5. To run the sample in package mode, from the command prompt, use the following command.

This builds `appdir`, `ext2rootfs`, the signed package and executes the application contained within the package
```
    make run
```

## Configuration parameters
A Mystikos package needs configuration to control certain run-time environmental settings as well as settings that control how the application reads environmental data from the insecure host environment.
This is the configuration for the helloworld sample. `ApplicationPath` states which executable should be run after the package is loaded. `MemorySize` is the amount of memory needed by the application to run.

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
    "ApplicationPath": "/bin/hello"
}
```
To learn more about configuration, please refer to related [documentation](../../doc/sign-package.md).
