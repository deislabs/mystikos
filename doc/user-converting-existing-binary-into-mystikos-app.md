# Converting an existing non-container binary into a Mystikos application

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

## Assumptions
1. You have an existing binary you want to run in mystikos
2. You do not wish to compile the binary again \
    If this is untrue, look into containerizing your application by building it in a container. Documentation for guides on how to do this: [C++](user-getting-started-docker-c++.md), [dotnet](user-getting-started-docker-dotnet.md), [python](user-getting-started-docker-python.md). If you are not working with one of these languages, you can still refer to one of them that you are most comfortable with to get a general idea of how to build an application in a docker container.


## Building the container

### Identifying the compatible docker OS image
A Dockerfile is simply a text-based script of instructions used to create a container image.
The first step in creating a Dockerfile is to identify the underlying OS image that we would like to pull to create our application. Docker has a library of practically any OS image you can think of. We will work to identify the image we want.

1. Navigate to their website [hub.docker.com](hub.docker.com).
2. Click on "Explore" on the top level bar to explore container images.
3. Filter by the categories of OS you wish to look for. Search by name if you know the OS image you are looking for. 
4. After identifying the required image, use it as a starting point for your container. E.g. if you identified the required OS to be ubuntu-18.04, use the statement `FROM ubuntu-18.04` as the first step in your Dockerfile.


### Identifying the dependencies your binary needs
Your binary could be dependant on certain libraries present on your system for proper execution. In order for mystikos to run your application in a Trusted Execution Environment(TEE), we need to have access to these dependencies as well. If you know the packages that your application would need to run, you can skip this section e.g. A program written in C would require gcc to be installed. Otherwise, here are a few handy tools to help identify the packages your application might depend on - 

#### 1. ldd
ldd prints the shared library dependencies for your linker on the command line. ldd shows the transitive closure of dependencies. \
E.g. In this example we are trying to find the dependencies in a test present in the libcxx2 test suite
```bash
 $ ldd appdir/app/llvm-project/libcxx/test/libcxx/atomics/atomics.flag/init_bool.pass.cpp.exe
        linux-vdso.so.1 (0x00007fffafe68000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffbf2100000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffbf26f3000)
```
This invocation tells us that this binary depends on these three shared object libraries which can be copied from the current system into the docker container or installed into the container directly as a package. \
Note: You can skip `linux-vdso.so.1` since this is a virtual ELF dynamic shared object file and does not have any physical file on the disk \
To copy them over, use the statement `COPY /location/of/shared/object /location/in/container/to/put/it`. \
To install them directly, do it like you would do on that OS anyway. e.g. `RUN apt-get update && apt-get install -y package-name` for ubuntu.

#### 2. readelf -d
readelf shows you exactly what dependencies the app wants, but this is not a transitive closure so you only get to know the immediate dependencies; it considers separate from dynamic dependency. In a nutshell it determines what the app needs from the host system.\
E.g. In this example we are trying to find the dependencies in a test present in the libcxx2 test suite
```bash
$ readelf -d appdir/app/llvm-project/libcxx/test/libcxx/atomics/atomics.flag/init_bool.pass.cpp.exe | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
```
This invocation tells us that we need to include the libc.so.6 shared object library in our docker container in order for it to be able to run our application. This does not include on-system dependencies such as linux-vdso.so.1 which we may not need to include if we are running on the same OS as the host we are judging on.


### Copy over the binary

The next step in this process would be to copy over the binary from the host system into the container using the same COPY command explained above. The statement would look like: 
```
COPY /location/of/binary/on/host /location/in/container/to/put/it
```

### Create the container

The final step in this process would be to create the container needed for the appbuilder. Coherently arrange the statements above so that: 
1. You have your base OS included
2. Include any dependencies required for your binary
3. Include any ENV VARs needed for invocation
4. Copy the binary you want to execute in mystikos from your host system into the container
5. Copy over any dynamically loaded files that you pass in as arguments, or config files, etc into the docker container as well

You can build and run the container app with the following command to make sure it's correct: \
`docker run $(docker build -q .) /cmd/to/run/binary <args-if-any>`

The process to create the container is simple, as defined by docker. You can simply let us handle it from there by invoking - 
```bash
myst-appbuilder Dockerfile
```

### Next steps

Next, you can create your filesystem archive (currently cpio or ext2fs) and run that in mystikos. Step to step #3 in the App development workflow [here](user-getting-started.md#app-development-workflow).
