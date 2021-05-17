#!/bin/bash
$* > stdout.txt
grep -v OE_ENCLAVE_ABORTING stdout.txt | diff - expected
if [ "$?" != "0" ]; then
    exit 1
fi
