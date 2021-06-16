#!/bin/bash
rm -f client.output

# wait for the server to launch and then run client command
while read -r line; do
  echo "$line"
  if echo $line | grep -q "$1"; then
    curl 127.0.0.1:8000 || exit 1
    touch client.output
    exit 0
  fi
done
