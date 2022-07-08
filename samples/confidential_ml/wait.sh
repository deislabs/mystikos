#!/bin/bash
while [ -z "${str}" ]
do
    str=$(lsof -i -P -n | grep "\<8000\>")
done
echo "Server created"
