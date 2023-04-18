# Mystikos samples

## Prerequsites to run samples

Follow the [installation guide](../README.md#installation-guide-for-ubuntu) to set up prerequsites for the samples.

[Download the Mystikos package from GitHub and set up the path](../README.md##install-from-released-package) as described in the documentation or [build Mystikos from source and install the package](../BUILDING.md).

## Common SGX Sample Information

Each sample has a Makefile. Build and run each sample by issuing a make command:

` make run `

## Developer Workflow

It is recommended that you understand the developer workflow for Mystikos by reading the [documentation](../doc/user-getting-started.md#app-development-workflow).

## SGX execution targets

The samples below demonstate how to run Mystikos samples using the SGX execution target. To learn more about the SGX execution target, please refer to 
the [documentation for the targets](../doc/user-getting-started.md#understand-mystikos-execution-targets).

## Samples

The following samples demonstate how Mystikos can be used to run applications in SGX.

* [Helloworld](./helloworld)
Demonstates how to build and run the simples C application in Mystikos.
Takes the developer through the steps of build a cpio application, an ext2 application, signing and packaging.

* [docker_aks](./docker_aks)
Demonstrates how to run a  Mystikos application from within a docker container either locally or in Azure Kubernetes Service.

* TEE Aware applications
    - [gencreds](./TEE_aware/gencreds) Shows an advanced developer how to write a TEE aware sample in C that can get a self signed certificate which can be used for attested_tls.
    - [dotnet](./TEE_aware/dotnet) Shows a developer how to get started with .NET applications for Mystikos. It also shows how a .NET application can retrieve TEE credentials for use.

* [java_hello_world](./java_hello_world)
Demonstrates how to build and run a Java application.

* [Pytorch and ONNX infrence](./pytorch_onnx_inference)
Demonstrates how to convert a Dockerfile into a root file system that can be run in Mystikos. Can run both a pytorch and an ONNX inference application. The sample is written in Python.

* [RUST](./rust)
Demonstrates running a RUST application.

* [Tensorflow_lite](./tensorflow_lite)
Demonstrates running a Tensorflow Lite application.The sample is written in Python.
