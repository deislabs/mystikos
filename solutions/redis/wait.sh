#!/bin/bash

PORT=$1

while [ -z "${str}" ]
do
    str=$(sudo lsof -i -P -n | grep "\<$PORT\>")
done
echo "Server created"
