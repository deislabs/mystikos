# Getting started with a containerized Python program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

**Disclaimer**: Mystikos's support for Python is incomplete.
We are working towards complete Python support.

The Python runtime versions we have tested most are 3.8 and 3.9. We recommend
users to develop/migrate their applications on/to these versions to work
with Mystikos.

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
FROM python:3.9-slim
RUN pip3 install numpy

WORKDIR /app
COPY ./hello.py /app

ENTRYPOINT ["python3", "hello.py"]
```

You can save the docker file to `Dockerfile` in the same folder as `hello.py`, and build
and run the container app with the following command:

`docker run $(docker build -q .)`

## Build the self-contained app folder with Mystikos

We use a script to take the same docker file and generates an
app folder `appdir` for preparing the program to be run with Mystikos.

```
myst-appbuilder Dockerfile
```
`appdir` contains the typical Linux root file system, such as `/usr`,
`/home`, `/bin`, etc. It also contains our application under `/app`.
The Python runtime and numpy are also included.

## Create a CPIO archive and run the program inside an SGX enclave in debug mode

```bash
myst mkcpio appdir rootfs
myst exec-sgx --memory-size 256m rootfs /usr/local/bin/python3 /app/hello.py
```

The `myst mkcpio` command creates a CPIO archive out of `appdir` and then launches
it as a file system. See [here](./user-getting-started-c.md#create-a-cpio-archive)
for details.

Through `--memory-size 256m` we tell Mystikos to operate with 256 mb heap size due
to the memory requirement of Python runtime. And on the `myst exec-sgx` command,
we also provide the full paths to the Python interpreter and the Python
application.

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

To run an application with Mystikos in release or production mode, please see
[packaging](./sign-package.md).

## Further readings

For more complex Python programs that are already working with Mystikos, please see:

* [A simple Python web server based on HttpServer](https://github.com/deislabs/mystikos/tree/main/solutions/python_webserver)
* [A Python web server based on Flask or uWSGI](https://github.com/deislabs/mystikos/tree/main/solutions/python_web_frameworks)
* [A Python application that uses pyodbc, pandas, pycurl, etc.](https://github.com/deislabs/mystikos/tree/main/solutions/python_app)
* [A PyTorch inference example](https://github.com/deislabs/mystikos/tree/main/samples/pytorch)
