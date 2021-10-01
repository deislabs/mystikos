#!/bin/bash

##==============================================================================
##
## This script squashes Mystikos application directories. It removes files that
## are not necessary for execution within a Mystikos root file system.
##
## Example:
##     squash-appdir.sh ./appdir
##
##==============================================================================

if [ "$#" != "1" ]; then
    echo "Usage: $0 <appdir-path>"
    exit 1
fi

appdir=$(realpath $1)

if [ "${appdir}" == "/" ]; then
    echo "$0: refusing to squash the system root directory"
    exit 1
fi

# Remove files with these extensions: .c, .h, .o, .a
rm -rf `find ${appdir} -name '*.[choa]'`

# Remove C++ files
rm -rf `find ${appdir} -name '*.cpp'`
rm -rf `find ${appdir} -name '*.hpp'`

# Remove .git directories
rm -rf `find ${appdir} -name '.git'`

# Remove include directories
rm -rf ${appdir}/usr/include
rm -rf ${appdir}/usr/local/include

# Remove gcc
rm -rf ${appdir}/usr/lib/gcc
rm -rf ${appdir}/usr/libexec/gcc


# Remove any files specified by .squash-appdir config file
config=$(dirname ${appdir})/.squash-appdir
if [ -f "${config}" ]; then
    rm -rf $(cat "${config}")
fi
