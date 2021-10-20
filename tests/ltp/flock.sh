#!/bin/bash

while true
do
    flock $*
    ret=$?
    echo "fffffffffffffffffffffff: flock return: ${ret}"
    exit ${ret}
done
