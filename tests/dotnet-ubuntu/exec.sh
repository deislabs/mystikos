#!/bin/bash
$*
ret=$?
TARGET=$8

if [ "$TARGET" == "sgx" -a "$ret" != "0" ]; then
    exit 1
fi

if [ "$TARGET" == "linux" ]; then
    if [ "$ret" == "134" -o "$ret" == "139" ]; then
        exit 0
    else
        exit 1
    fi
fi
