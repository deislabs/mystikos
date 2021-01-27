# Getting started with a containerized C# program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

**Disclaimer**: Mystikos's support for dotnet and C# is incomplete.
We are working towards complete C# support.

## Write the program

In this example, we take numbers from command line and output the sum.
C# requires us to create a project first. First we need to install dotnet
SDK 3.1 with `sudo apt install dotnet-sdk-3.1`. Then run the command:

```
dotnet new console -o sum
```

After we have the folder `sum` ready, open `Program.cs` in it, and replace
its content with the following code:

```c#
using System;
using System.Collections.Generic;

namespace sum
{
    class Program
    {
        static void Main(string[] args)
        {
			long sum = 0;
			List<long> numbers = new List<long>();
			for (int i = 0; i < args.Length; i++)
			{
				numbers.Add(Int64.Parse(args[i]));
				sum += numbers[numbers.Count - 1];
		    }
		    Console.WriteLine($"Hello World from C#! Sum is {sum}\n");
        }
    }
}
```

You can build and run the program on Ubuntu with the following command
to make sure it's correct:

```
cd sum
dotnet build -o build
dotnet build/sum.dll 1 2 3
```

The expected outputs is a welcome message and the sum of the command line arguments:

`Welcome to C#! Sum is 6`


## Containerize the program

We provide a docker file for building and running the application as follows.
Note this is a multi-stage dockerfile as `dotnet SDK` is only required for
building. Running the application requires `dotnet runtime`, a much smaller
package. We can use it in the run stage to save space.

```docker
# stage 1: build
FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /app
COPY . .
RUN dotnet publish -o publish -r linux-musl-x64 /p:PublishTrimmed=true

# stage 2: run
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine
WORKDIR /app

RUN apk add --no-cache icu-libs
COPY --from=build /app/publish .

ENTRYPOINT [ "dotnet", "/app/sum.dll", "1", "2", "3" ]
```

It you have an existing docker file for your application running on an
Ubuntu-based container, some adjustments are needed to run it on
an Alpine Linux based container, which happens to be compatible with
Mystikos (they both use MUSL as C-runtime).

* During the build stage, we need to tell the compiler that we are cross
compiling for Alpine Linux with the switch `-r linux-musl-x64`
* Also in the building stage, we recommend switch `/p:PublishTrimmed=true`
to generate less files for the application. SGX has limited EPC memory,
this switch helps to save memory space.
* At the run stage, the base image should be changed
to `mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine`
(or other supported versions).
* Also at the run stage, we have to explicitly install packages required
by dotnet runtime or the application but aren't included in the base image.
Keep in mind that not every package you find on Ubuntu is available on Alpine
Linux, which is a less popular distro than Ubuntu.

You can save the docker file to the `sum` folder, and build and run the
container app on Linux with the following command:

`docker run $(docker build -q .)`

## Build the app folder with Mystikos

We use a script to take the same docker file and generates an
app folder `appdir` for preparing the program to be run with Mystikos.

```
myst-appbuilder Dockerfile
```
`appdir` contains the typical Linux root file system, such as `/usr`,
`/home`, `/bin`, etc. It also contains our application under `/app`.
The dotnet runtime is also included.

## Package the application

dotnet runtime requires more heap memory than Mystikos provides
by default. To expand the memory, we need to sign or package the application
with a configuration file, in which a higher limit of user heap size
can be specified as follows:
```
{
	// OpenEnclave specific settings
	"Debug": 1,
    "KernelMemSize": "8m",
    "StackMemSize": "400k",
    "NumUserThreads": 8,
    "ProductID": 1,
    "SecurityVersion": 1,

	// Mystikos specific settings
    // The heap size of the user application. Increase this setting if your app experienced OOM.
    "UserMemSize": "512m",
    // The path to the entry point application in rootfs
    "ApplicationPath": "/usr/bin/dotnet",
    // The parameters to the entry point application
    "ApplicationParameters": ["/app/sum.dll"],
    // Whether we allow "ApplicationParameters" to be overridden by command line options of "myst exec"
    "HostApplicationParameters": true,
}
```
You can ignore most of the settings for now except for `UserMemSize`. 512 MB is the minimum required
by dotnet runtime, and you can increase it as needed. For details of the config file, please refer to
[signing and packaging](./sign-package.md)

Save the above config file to `config.json`, and package the app with:
```
openssl genrsa -out private.pem -3 3072
myst package appdir private.pem config.json
```

## Run the program inside a SGX enclave

Packaging produces an executable under `$PWD/myst/dotnet`, which can be launched
like any system-installed dotnet runtime (except the execution actually happens in a TEE):
```
myst/bin/dotnet /app/sum.dll 1 2 3
```

The expected outputs, not surprisingly, is ``Welcome to C#! Sum is 6``

Congratulations! You have written a confidential application in a
high level programming language, and you have launched it, together with
a managed runtime, within a TEE.
