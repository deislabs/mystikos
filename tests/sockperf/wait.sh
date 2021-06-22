#!/bin/bash
while [ -z "${str}" ]
do
    str=$(sudo lsof -i -P -n | grep "\<11111\>")
done
echo "Server created"
