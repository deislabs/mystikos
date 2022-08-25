#!/bin/bash

# Run program passed in cmdline args
$*

# expected error code is 2
if [ "$?" != "2" ]; then
    exit 1
fi
