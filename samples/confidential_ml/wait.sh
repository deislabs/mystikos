#!/bin/bash
# This waits for the server to start. For example:
# * Running on http://127.0.0.1:8000

count=0
# Wait for a max of 300 seconds
max_seconds=300

while [ -z "${str}" ]
do
    str=$(lsof -i -P -n | grep "\<8000\>")
    sleep 1
    count=$((count+1))
    if [ $count -gt $max_seconds ]; then
        echo "Server failed to start within the time limit. Exiting."
        exit 1
    fi
done
echo "Server created"
