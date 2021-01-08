# Docker build environment for Mystikos

The files in this directory contain all that is needed to complete a product binary build of Mystikos within docker.
It does not do the normal developer build because that builds tests that are not needed and Docker itself is needed for the test pieces that are not needed for just the product binaries itself.

If running from this directory you would build the Docker image with a command similar to this:

```bash
docker build -t image-name:latest .
```

This builds the docker image using `Dockerfile`.
This installs all the system components that are needed to build Mystikos and dependent modules.
Most of the components are actually installed by is pulling down a temporary copy of the Open Enclave repository from github.com and running the ansible configuration scripts from there.
Mystikos does not have any other required dependencies over and above those.

The building of the image also includes `build-myst.sh` into the image which is what gets run to do the actual build during the running of the Docker image.

Currently the Mystikos source is a private repository making it a little harder to get to the source automatically.
For now we mount the Mystikos source code into the container at run-time.

We have the image from the previous command.
Now, if we run from the current directory in the Mystikos repository, a command similar to this would be run:

```bash
docker run  --rm  --tty --interactive  -v /../..:/src:rw image-name:latest
```

This command uses the `-v from:to` option to mount the root of the Mystikos source into the `/src/` directory inside the container. It should be noted that this is mounted as read/write.
This is the directory the script expects the source to be and runs the `make` commands against that source.

The results of this there will be `build` directory under the root of the Mystikos source where the binaries will be present. Currently this includes all the intermediate build artifacts too.
