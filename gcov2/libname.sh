#!/bin/bash

# find the full path of the system libgcov.a

tempfile=$(/bin/mktemp --suffix=.c)
echo "int main() { return 0; }" > ${tempfile}

gcc -Wl,-trace ${tempfile} -lgcov | grep libgcov.a
if [ "$?" != "0" ]; then
    echo "$0: gcc failed"
    exit 1
fi

rm -f ${tempfile}
