# Getting started with a containerized Python program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

**Disclaimer**: Mystikos's support for Python is incomplete.
We are working towards complete Python support.

## Write the program

In this example, we print number 0-100 in a square:

```python
import numpy as np
a = np.arange(100).reshape(10, 10)
print(a)
print("Welcome to Python and numpy!")
```

After save it to `hello.py`, you can build and run the program on Ubuntu
with the following command (after installing `python` and `numpy`) to make
sure it's correct: `python3 hello.py`

The expected outputs are a welcome message and the square of integers:

```
[[ 0  1  2  3  4  5  6  7  8  9]
 [10 11 12 13 14 15 16 17 18 19]
 [20 21 22 23 24 25 26 27 28 29]
 [30 31 32 33 34 35 36 37 38 39]
 [40 41 42 43 44 45 46 47 48 49]
 [50 51 52 53 54 55 56 57 58 59]
 [60 61 62 63 64 65 66 67 68 69]
 [70 71 72 73 74 75 76 77 78 79]
 [80 81 82 83 84 85 86 87 88 89]
 [90 91 92 93 94 95 96 97 98 99]]
Welcome to Python and numpy!
```

## Containerize the program

We provide a docker file for building and running the application as follows.

```docker
FROM python:3-alpine

RUN apk add build-base py3-pip

WORKDIR /app
COPY ./hello.py /app
RUN /usr/local/bin/pip install numpy
ENTRYPOINT ["python3", "hello.py"]
```

It you have an existing docker file for your application running on an
Ubuntu-based container, some adjustments are needed to run it on
an Alpine Linux based container, which happens to be compatible with
Mystikos (they both use MUSL as C-runtime).

* The base image should be changed to `python:3-alpine`
(or other supported versions for Alpine Linux).
* We have to explicitly install required packages for numpy.

Currently we need to install `build-base` and `py3-pip`, and then
in turn use them to install `numpy`. The installation of numpy builds it
from source thus takes quite some time. We are looking for ways to improve
the performance.

Keep in mind that not every package you find on Ubuntu is available on Alpine
Linux, which is a less popular distro than Ubuntu.

You can save the docker file to the same folder as `hello.py`, and build
and run the container app on Linux with the following command:

`docker run $(docker build -q .)`

## Build the app folder with Mystikos

We use a script to take the same docker file and generates an
app folder `appdir` for preparing the program to be run with Mystikos.

```
myst-appbuilder Dockerfile
```
`appdir` contains the typical Linux root file system, such as `/usr`,
`/home`, `/bin`, etc. It also contains our application under `/app`.
The Python runtime is also included.

## Run the program inside a SGX enclave

We need to create a CPIO archive out of `appdir` and then launch it as
a file system. See [here](./user-getting-started-c.md#create-a-cpio-archive)
for details.

```bash
myst mkcpio appdir rootfs
myst exec rootfs /usr/local/bin/python3 /app/hello.py
```

The expected outputs, not surprisingly, is:
```
[[ 0  1  2  3  4  5  6  7  8  9]
 [10 11 12 13 14 15 16 17 18 19]
 [20 21 22 23 24 25 26 27 28 29]
 [30 31 32 33 34 35 36 37 38 39]
 [40 41 42 43 44 45 46 47 48 49]
 [50 51 52 53 54 55 56 57 58 59]
 [60 61 62 63 64 65 66 67 68 69]
 [70 71 72 73 74 75 76 77 78 79]
 [80 81 82 83 84 85 86 87 88 89]
 [90 91 92 93 94 95 96 97 98 99]]
Welcome to Python and numpy!
```

Congratulations! You have written a Python application and
successfully launched it in a TEE.
