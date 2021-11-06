# Machine Learning Inference sample in Python running in Mystikos

This sample demonstrates how a machine learning model can be donwloaded into an enclave and
how an inferencing server can be run from within an enclave. It is written in python.

It is recommended that you understand how to use EXT2 file system and how applications can be packaged for
Mystikos before proceeding witht his sample. Please refer to the README for the helloworld sample
to obtain the necessary information.

## Transform a Dockerfile into a root file system
`Dockerfile.rootfs` sets up all the prerequsites to use ONNX and Pytorch inside a Python program.
`myst-appbuilder` is used to convert the Dockerfile into a directory containing all the files needed to run this application in Mystikos.
```
myst-appbuilder -v -d Dockerfile.rootfs
```

After this, the `appdir` generated can be converted into a cpio archive using `myst mkcpio` or an EXT2 file system using `myst mkext2`that can be loaded into Mystikos.
In this sample, we use an EXT2 file system.

## Functionality 

This sample downloads the AlexNet model in `.pt` format and exports it to `.onnx`
format. This is executed outside the enclave (`src/download_pretrained_model.py`).

A server(`src/server_app.py`) is launched inside the enclave with the packaged model files.
A client(`client.sh`) sends image files to the server. The server processes it through the
inferencing service running inside the enclave(`src/inference_service.py`) and returns the inference results
to the client.

The server will return the inference results for both PyTorch and ONNX Runtime.

## Configuration parameters
A Mystikos package needs configuration to control certain run-time environmental settings as well as settings that control how the application reads environmental data from the insecure host environment.
This sample needs more memory than helloworld. `ApplicationPath` sensures that python3 is run after the root file system is mounted. 

```
{
    "Debug": 1,
    "ProductID": 1,
    "SecurityVersion": 1,
    "UserMemSize": "2048m",
    "CurrentWorkingDirectory": "/app",
    "ApplicationPath": "/home/user/miniconda/bin/python3",
    "ApplicationParameters": ["/app/service_app.py"]
}
```
## Running the sample

To run the sample in package mode, use `make run` to launch both the server and the local client that will
send images located inside `test_samples` for inferencing.

To run the sample using `myst exec-sgx`, use `make runexec`.

To run the sample using `myst exec-sgx`, use `make runexec`. Note that the `myst-exec` command takes the application configuration as a parameter
```
@myst exec-sgx $(OPTS) ext2rootfs $(APP_PATH) --app-config-path config.json
```
This is because additional application configuration such as the the application parameters and environmental variables are supplied by config.json.
