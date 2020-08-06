#!/bin/bash

IMAGE_NAME="$1"
RESULT_NAME="$2"

set -e
set -x

# Download the docker image from github
fetch_image()
{
	groups | grep docker >/dev/null
	if [ "$?" -ne "0" ]; then
		echo "Must be a member of the 'docker' group"
		exit 1
	fi

	docker pull $IMAGE_NAME
}

# export a flattened copy of the container
# note that we have to start up the image to flatten it
# TODO: there's probably a fancier way to do this with more time
export_image()
{
    docker run -d --name temp-extract $IMAGE_NAME
    docker stop temp-extract

    docker export temp-extract -o temp-extract.tar
    docker rm temp-extract
}

# convert the flattened tar into a cpio
make_cpio()
{
    rm -rf appdir && mkdir appdir && cd appdir
    tar xf ../temp-extract.tar
    cd ..
    libos mkcpio appdir $RESULT_NAME
}

# delete artifacts
clean_up()
{
    rm -rf appdir
    rm -f temp-extract.tar
}

# run the commands, or comment out as needed
fetch_image
export_image
make_cpio
clean_up
