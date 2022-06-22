#!/bin/bash
while [ -z "${str}" ]
do
    sleep 2
    str=$(sudo lsof -i -P -n | grep "\<5000\>")
done
echo "Server created"
