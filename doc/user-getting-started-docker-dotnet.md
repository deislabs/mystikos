# Getting started with a containerized C# program

Please see [README](../README.md) for how to install Mystikos or build
it from source code.

**Disclaimer**: Mystikos's support for dotnet and C# is incomplete.
We are working towards complete C# support.

The most tested dotnet runtime versions by us are the 3.1 LTS and 5.0 releases. We
recommend users to develop/migrate their applications on/to this version
to work with Mystikos.

## Write the program

In this example, we take numbers from command line and output the sum.
C# requires us to create a project first. First we need to install dotnet
SDK with -

For .Net 3.1:
```
sudo apt install dotnet-sdk-3.1
```

For .Net 5:
```
sudo apt install dotnet-sdk-5.0`.
```

Then run the command:

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

You can build and run the program with the following command
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

### .Net 3.1 Dockerfile

```docker
# stage 1: build
FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /app
COPY . .
RUN dotnet publish -o publish

# stage 2: run
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-bionic
WORKDIR /app

COPY --from=build /app/publish .

ENTRYPOINT [ "dotnet", "/app/sum.dll", "1", "2", "3" ]
```

### .Net 5.0 Dockerfile

```docker
# stage 1: build
FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /app
COPY . .
RUN dotnet publish -o publish

# stage 2: run
FROM mcr.microsoft.com/dotnet/aspnet:5.0
WORKDIR /app

COPY --from=build /app/publish .

ENTRYPOINT [ "dotnet", "/app/sum.dll", "1", "2", "3" ]
```

You can save the docker file to the `sum` folder, and build and run the
container app with the following command:

`docker run $(docker build -q .)`

## Build the self-contained app folder with Mystikos

We use a script to take the same docker file and generates an
app folder `appdir` for preparing the program to be run with Mystikos.

```
myst-appbuilder Dockerfile
```
`appdir` contains the typical Linux root file system, such as `/usr`,
`/home`, `/bin`, etc. It also contains our application under `/app`.
The dotnet runtime is also included.

## Create a CPIO archive, create configuration, and run the program inside an SGX enclave in debug mode

```bash
myst mkcpio appdir rootfs
echo """
{ 
    // Whether we are running myst+OE+app in debug mode
    "Debug": 1,
    "ProductID": 1,
    "SecurityVersion": 1,

    // Mystikos specific values

    // The heap size of the user application. Increase this setting if your app experienced OOM.
    "MemorySize": "1024M",
    "ThreadStackSize": "256k", // Native pthread stack size
    // Uncomment following config if running a multi-process application
    // "NoBrk": true, 
    // Whether we allow "ApplicationParameters" to be overridden by command line options of "myst exec"
    "HostApplicationParameters": true,
    // The environment variables accessible inside the enclave.
    "EnvironmentVariables": [
        "COMPlus_EnableDiagnostics=0",
        "COMPlus_GCHeapHardLimit=0x0400000"
    ]
}
""" > config.json
myst exec-sgx --app-config-path config.json rootfs /usr/bin/dotnet /app/sum.dll 1 2 3
```

On the last command, we pass in `--app-config-path config.json`, to specify all the required configuration required to run the application. This includes parameters to control resources which Mystikos controls - like memory size and thread stack size; and also environment variables which can be used to control dotnet runtime behavior or be used by the application being run.

More information about recommended configurations for dotnet applicatios can be found in the [dotnet support and limitations document](./dotnet-support.md).

We also pass in the full path to the `dotnet` executable and the application
dll to avoid ambiguity from duplicated file names.

The expected outputs, not surprisingly, is ``Welcome to C#! Sum is 6``

Congratulations! You have written a confidential application in a
high level programming language, and you have launched it, together with
a managed runtime, within a TEE.

To run an application with Mystikos in release or production mode, please see
[packaging](./sign-package.md).

## Further readings

For more complex dotnet programs that are already working with Mystikos, please see:

* [A web service based on ASP.net](https://github.com/deislabs/mystikos/tree/main/solutions/aspnet)
* [A web client that queries a remote attestation service](https://github.com/deislabs/mystikos/tree/main/solutions/dotnet/HelloWorld)
* [An example written with Azure SDK for dotnet](https://github.com/deislabs/mystikos/tree/main/solutions/dotnet_azure_sdk)