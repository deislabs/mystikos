# TensorFlow_lite sample in Python running in Mystikos

This sample demonstrates how to invoke TensowFlow_lite to label images from within an enclave. It is written in python.

It is recommended that you understand how to use EXT2 file system and how applications can be packaged
Mystkos before proceeding with this sample. Please refer to the README for the helloworld sample
to obtain the necessary information.

## Transform a Dockerfile into a root file system

`Dockerfile.slim.buster` sets up all the prerequsites to use Tensowflow. It downloads a photo, model and labels.
`myst-appbuilder` is used to convert the Dockerfile into a directory containing all the files needed to run this application in Mystikos.
```
myst-appbuilder -v -d Dockerfile.slim.buster
```

After this, the `appdir` generated can be converted into a cpio archive using `myst mkcpio` or an EXT2 file system using `myst mkext2`that can be loaded into Mystikos.
In this sample, we use an EXT2 file system.

After this, the `appdir` generated can be converted into a cpio archive using `myst mkcpio` or an EXT2 file system using `myst mkext2`that can be loaded into Mystikos.
In this sample, we use an EXT2 file system. Please refer to the README for the helloworld sample for information on the EXT2 file system.

## Functionality 

`label_image.py` takes an image ( in this sample, an image of Grace Hopper is used) and runs it through a MobileNetV1 model.
It then prints out the top 5 labels that match the image.

## Configuration parameters

A Mystikos package needs configuration to control certain run-time environmental settings as well as settings that control how the application reads environmental data from the insecure host environment.
This sample needs more memory than helloworld. `ApplicationPath` ensures that python3 is run after the root file system is mounted. The model, labels and image are sent in via `ApplicationParameters`.
`EnvironmentVariables` is used to set up the environment variables for use inside Mystikos.

```
{
    "Debug": 1,
    "ProductID": 1,
    "SecurityVersion": 1,
    "UserMemSize": "2048m",
    "ApplicationPath": "/usr/local/bin/python3",
    "ApplicationParameters": ["/app/label_image.py",
        "--model_file", "/tmp/mobilenet_v1_1.0_224.tflite",
        "--label_file", "/tmp/labels.txt",
        "--image", "/tmp/grace_hopper.bmp"],
    "EnvironmentVariables": ["PYTHONPATH=/usr/lib/python3/dist-packages"]
}
```
To learn more about configuration, please refer to related [documentation](../../doc/sign-package.md).

## Running the sample

To run the sample in package mode, use `make run`.

To run the sample using `myst exec-sgx`, use `make runexec`. Note that the `myst-exec` command takes the application configuration as a parameter
```
@myst exec-sgx ext2rootfs /usr/local/bin/python3 --app-config-path config.json
```
This is because additional application configuration such as the the application parameters and environmental variables are supplied by config.json.
