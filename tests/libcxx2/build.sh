#!/bin/bash

set -x
rm appdir2/test
g++ -std=c++17 test.cpp -pthread -fPIC -o test
cp test appdir2
rm rootfs2
../../build/bin/myst mkext2 appdir2 rootfs2
../../build/bin/myst exec-sgx --nobrk rootfs2 /test
set +x