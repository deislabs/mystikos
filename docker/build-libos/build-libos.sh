#! /bin/bash

# fail on error
set -e

# get the repo -- currently private so cannot
#cd /src
#git clone --recurse-submodules https://github.com/mikbras/oe-libos.git
#cd oe-libos

# As cannot get repo lets fall back to it being mounted
cd /src

# make the binaries
make clean
make LIBOS_PRODUCT_BUILD=1
