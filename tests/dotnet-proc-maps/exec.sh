#!/bin/bash
$* > stdout.txt
if [ "$?" != "0" ]; then
    exit 1
fi
grep -q "HelloWorld" stdout.txt
if [ "$?" != "0" ]; then
    exit 1
fi
