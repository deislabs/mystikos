#!/bin/bash
while [ -z "${str}" ]
do
    str=$(sudo lsof -i -P -n | grep "\<8000\>")
done
