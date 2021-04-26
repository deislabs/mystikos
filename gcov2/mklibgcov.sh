#!/bin/bash

##==============================================================================
##
## copy the system libgcov.a to ./libgcov.a
##
##==============================================================================

rm -rf ./libgcov.a

tmpsrc=$(/bin/mktemp --suffix=.c)
echo "int main() { return 0; }" > ${tmpsrc}

tmpmain=$(/bin/mktemp)
libgcov=$(gcc -o${tmpmain} -Wl,-trace ${tmpsrc} -lgcov | grep libgcov.a)

rm -f "${tmpmain}"
rm -f "${tmpsrc}"

if [ ! -f "${libgcov}" ]; then
    echo "$0: cannot find the system libgcov.a"
    exit 1
fi

cp "${libgcov}" ./libgcov.a

##==============================================================================
##
## prefix all C symbols in libgcov.a with "gcov_" prefix
##
##==============================================================================

if [ ! -f "libgcov.a" ]; then
    echo "$0: libgcov.a not found"
    exit 1
fi

ar xf libgcov.a
if [ "$?" != "0" ]; then
    echo "$0: failed to extract libgcov.a"
    exit 1
fi

objs=$(ls _gcov*.o)

for i in ${objs}
do
    objcopy --redefine-syms=redefine.syms $i
    if [ "$?" != "0" ]; then
        echo "$0: objcopy failed"
        exit 1
    fi
done

ar rf libgcov.a _gcov*.o
if [ "$?" != "0" ]
then
    echo "$0: failed to build libgcov.a"
    exit 1
fi

rm -f ${objs}

echo "Created libgcov.a"
