#! /bin/bash

# fail on error
set -e

# cd to mounted repo root
cd /src

# make the binaries
make distclean
make
