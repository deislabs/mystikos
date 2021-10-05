#!/bin/bash

set -x
g++ -std=c++17 test.cpp -pthread -fPIC -o test
cp test appdir2
rm rootfs2
# ../../build/bin/myst mkext2 appdir2 rootfs2
../../build/bin/myst exec-sgx --nobrk appdir2 /test
set +x