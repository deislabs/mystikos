#!/bin/bash

IMAGE_NAME='nimmis/alpine-micro:latest'

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
    docker run -d --name alpine-mariadb $IMAGE_NAME
    docker stop alpine-mariadb

    docker export alpine-mariadb -o alpine-mariadb.tar
    docker rm alpine-mariadb
}

# convert the flattened tar into a cpio
# NOTE: dereferencing the symlinks using rsync is possible but
#       results in a >600MB file
make_cpio()
{
    CWD=`pwd`
    TEMP=`mktemp -d`
    pushd $TEMP
    tar xf $CWD/alpine-mariadb.tar
    
    #NTEMP=`mktemp -d`
    #popd && rsync -Lr $TEMP/ $NTEMP/ && rm -rf $TEMP && mv $NTEMP $TEMP && pushd $TEMP

    find . | cpio --create --format='newc' > $CWD/rootfs
    popd
    rm -rf $TEMP
}

# delete artifacts
clean_up()
{
    rm -f alpine-mariadb.tar
}

# run the commands, or comment out as needed
fetch_image
export_image
make_cpio

