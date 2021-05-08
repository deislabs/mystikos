#!/bin/bash

##==============================================================================
##
## mklibgcov.sh
##
##     This script transforms the system libgcov.a into a local version whose
##     C symbols have been redefined to bear the "myst_gcov_" prefix. This will
##     allow libgcov.a to be used in contexts where these functions have
##     different behaviors.
##
##==============================================================================

if [ "$#" != "1" ]; then
    echo "Usage: $0 <gcov_lib_name>"
    exit 1
fi

libname=$1

##==============================================================================
##
## copy the system libgcov.a to ./libmystgcov.a
##
##==============================================================================

rm -rf ./libgcov.a

version=$(gcc -dumpversion)
if [ -z "${version}" ]; then
    echo "$0: failed to get gcc version"
    exit 1
fi

libgcov=/usr/lib/gcc/x86_64-linux-gnu/${version}/libgcov.a
if [ ! -f "${libgcov}" ]; then
    echo "$0: cannot find the system libgcov.a"
    exit 1
fi

cp "${libgcov}" "${libname}"

##==============================================================================
##
## prefix all C symbols in libmystgcov.a with "myst_gcov_" prefix
##
##==============================================================================

if [ ! -f "${libname}" ]; then
    echo "$0: ${libname} not found"
    exit 1
fi

ar xf ${libname}
if [ "$?" != "0" ]; then
    echo "$0: failed to extract ${libname}"
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

ar rf ${libname} _gcov*.o
if [ "$?" != "0" ]
then
    echo "$0: failed to build ${libname}"
    exit 1
fi

rm -f ${objs}

echo "Created ${libname}"
