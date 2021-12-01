# gencreds -  a TEE-aware program for Mystikos in C

This sample guides users to create TEE-aware applications, which are
essential to many confidential computing scenarios.

It is recommended that you understand how to use EXT2 file system and how applications can be packaged
Mystkos before proceeding with this sample. Please refer to the README for the helloworld sample
to obtain the necessary information.


## Set up pre-requisites

It is essential for this program to be able to find Mystikos header files installed as part of the Mystikos package.
To ensure that the Makefile can find the headers, export a variable `MYSTIKOS_INSTALL_DIR` and set it to the path of
the Mystikos installation on the system. As an example, if Mystikos is installed on /opt/mystikos, then issue
 the following command on the command prompt:

```cmd

export MYSTIKOS_INSTALL_DIR=/opt/mystikos

```
## Functionality

This sample demonstrates how a developer can write a program that distinguishes between running inside a TEE and a non TEE environment.
To understand more about the problem statement, please refer to the [TEE aware application documentation](../../../doc/user-getting-started-tee-aware.md).


### Write a program that behaves differently for TEE and non-TEE

This example shows how to write a program that potentially performs secret
operations only when running inside a TEE.

Here is a code snippet inside `gencreds.c`.

```c
    if ( !target )
    {
       printf("****I am in unknown environment, returning\n");
       return 0;
    }
    if (strcmp(target, "sgx") != 0)
    {
        printf("****I am in non-TEE, returning\n");\
        return 0;
    }
    else
    {
        printf("****I am in an SGX TEE, I will proceed to generate and verify TEE credentials\n");\
```



## Run the program

In the Makefile, the make run command runs the program outside of Mystikos and inside Mystikos
```
	echo "Running application outside a TEE."
	appdir/bin/gencreds
	echo "Running Mystikos packaged application inside an SGX TEE."
	./myst/bin/gencreds
```

Issue the `make run` command.

Here is the output:
```
Running application outside a TEE.
appdir/bin/gencreds
***I am in unknown environment, returning
echo "Running Mystikos packaged application inside an SGX TEE."
Running Mystikos packaged application inside an SGX TEE.
./myst/bin/gencreds
****I am in an SGX TEE, I will proceed to generate and verify TEE credentials
```

## Generating and verifying self-signed certificates programmatically

When an application is operating in a TEE, there are several cases when the application must generate or verify TEE credentials.

To learn more about the use cases and understand why this is needed, please refer to the [TEE aware application documentation](../../../doc/user-getting-started-tee-aware.md).


Issue the `make run` command in order to generate and verify the certificate.

## Configuration parameters

A Mystikos package needs configuration to control certain run-time environmental settings as well as settings that control how the application reads environmental data from the insecure host environment.
This sample needs about the same memory as helloworld. `ApplicationPath` ensures that gencreds is run after the root file system is mounted. 

```
{
    // Mystikos configuration version number
    "version": "0.1",

    // OpenEnclave specific values
    "Debug": 1,
    "ProductID": 1,
    "SecurityVersion": 1,

    // Mystikos specific values
    "MemorySize": "40m",
    "ApplicationPath": "/bin/gencreds"
}
```
To learn more about configuration, please refer to related [documentation](../../doc/sign-package.md).

## Running the sample

To run the sample in package mode, use `make run`.

To run the sample using `myst exec-sgx`, use `make runexec`.