#!/bin/bash
exit 64
while [ -z "${str}" ]
do
    str=$(sudo lsof -i -P -n | grep "\<5050\>")
done
echo "Server created"
