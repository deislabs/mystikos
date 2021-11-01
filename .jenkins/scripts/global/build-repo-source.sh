#!/bin/bash

make distclean
make -j build

rm build/bin/myst-lldb build/bin/myst-gdb
cp build/openenclave/bin/oelldb build/bin/myst-lldb
cp build/openenclave/bin/oegdb build/bin/myst-gdb
