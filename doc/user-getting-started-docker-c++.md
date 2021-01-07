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

We provide a docker file for building and running the application as follows.
Note this is a multi-stage dockerfile as `boost-dev` is only required for
building. We can skip it in the final image to save space.

```docker
# stage 1 build
FROM alpine:3.10 AS base-image

RUN apk add --no-cache build-base boost-dev

WORKDIR /app
ADD square.cpp .
RUN g++ square.cpp -o square

# stage2 get binaries
FROM alpine:3.10

RUN apk add --no-cache libstdc++

COPY --from=base-image /app/square /square

CMD ["/square", "1", "2", "3"]
```

It you have an existing docker file for your application running on an
Ubuntu-based container, some minor adjustments are needed to run it on
an Alpine Linux based container, which happens to be compatible with
Mystikos (they both use MUSL as C-runtime).

For example, the base image should be changed from maybe `ubuntu:18.04`
to `alpine:3.10`. Also instead of `apt install <package list>`, we use
Alpine Linux's installer `apk add <package list>`. Keep in mind that not
every package you find on Ubuntu is available on Alpine Linux, which is
a less popular distro than Ubuntu.

You can build and run the container app on Linux with the following command
to make sure it's correct:

`docker run $(docker build -q .)`

The expected outputs, again, are "1 4 9".

## Build the app folder with Mystikos

We use a script to take the same docker file and generates
an app folder `appdir` for preparing the program to be run with Mystikos.

```
myst-appbuilder Dockerfile
```
`appdir` contains the typical Linux root file system, such as `/usr`,
`/home`, `/bin`, etc. It also contains our application `square` under
the root directory. The C++ runtime library `libstdc++` is also included.

## Create a CPIO archive and run the program inside a SGX enclave

These two steps are almost identical to the descriptions
[here](./user-getting-started-c.md#create-a-cpio-archive)
```
myst mkcpio appdir rootfs
myst exec-sgx rootfs /square 1 2 3
```

The expected outputs, not surprisingly, are "1 4 9". But perhaps we have more
confidence in the answer because we just run the program in a TEE!
