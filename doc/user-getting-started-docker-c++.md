# Getting started with a containerized C++ program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

## Write the program

To be more interesting than `Hello World`, we use `boost` to compute the
squares of a few numbers. Save the following to a file `square.cpp`.

```c++
#include <iostream>
#include <algorithm>
#include <boost/lambda/lambda.hpp>

using namespace std;

int main(int argc, char* argv[])
{
    vector<int> v;
    for(int i = 1; i < argc; i++)
        v.push_back(atoi(argv[i]));

    for_each(v.begin(), v.end(),
        cout << boost::lambda::_1*boost::lambda::_1 << " ");

    cout << endl;
    return 0;
}
```

You can build and run the program on Ubuntu with the following command
(after `sudo apt install libboost-dev`) to make
sure it's correct:

`g++ square.cpp -o square && ./square 1 2 3`

The expected outputs, of course, are "1 4 9".


## Containerize the program

We provide a `Dockerfile` for building and running the application as follows.
Note this is a multi-stage dockerfile as `boost-dev` is only required for
building. We can skip it in the final image to save space. 
> :warning: In this example we use Ubuntu 18.04, but you should use the latest supported Ubuntu LTS version instead.

```docker
# stage 1 build
FROM ubuntu:18.04 AS base-image

RUN apt update && apt install -y g++ libboost-all-dev

WORKDIR /app
ADD square.cpp .
RUN g++ square.cpp -o square

# stage2 get binaries
FROM ubuntu:18.04

RUN apt install libstdc++

COPY --from=base-image /app/square /square

CMD ["/square", "1", "2", "3"]
```

The docker file uses Ubuntu:18.04 as the base image as an example. But we
could also use other Linux distros, e.g., Alpine Linux, as the base image.

You can build and run the container app with the following command
to make sure it's correct:

`docker run $(docker build -q .)`

The expected outputs, again, are "1 4 9".

## Build the self-contained app folder with Mystikos

We use a script to take the same docker file and generate
an app folder `appdir` for preparing the program to be run with Mystikos.

```
myst-appbuilder Dockerfile
```
`appdir` contains the typical Linux root file system, such as `/usr`,
`/home`, `/bin`, etc. It also contains our application `square` under
the root directory. The C++ runtime library `libstdc++` is also included.

## Create a CPIO archive and run the program inside an SGX enclave in debug mode

These two steps are almost identical to the descriptions
[here](./user-getting-started-c.md#create-a-cpio-archive)
```
myst mkcpio appdir rootfs
myst exec-sgx rootfs /square 1 2 3
```

The expected outputs, not surprisingly, are "1 4 9". But perhaps we have more
confidence in the answer because we just ran the program in a TEE!

To run an application with Mystikos in release or production mode, please see
[packaging](./sign-package.md).

## Further readings

For more complex C++ programs that are already working with Mystikos, please see:

* [The test suite for msgpack for C++](https://github.com/deislabs/mystikos/tree/main/solutions/msgpack_c)
* [The test suite for Azure SDK for C++](https://github.com/deislabs/mystikos/tree/main/tests/azure-sdk-for-cpp)
* [The C++ test suite for llvm project](https://github.com/deislabs/mystikos/tree/main/tests/libcxx)
