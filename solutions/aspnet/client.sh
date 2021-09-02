#!/bin/bash
rm -f client.output

curl 127.0.0.1:5050 || exit 1
sleep 1
curl 127.0.0.1:5050 || exit 1
sleep 1
curl 127.0.0.1:5050 || exit 1
sleep 1
curl 127.0.0.1:5050 || exit 1
sleep 1
curl 127.0.0.1:5050 || exit 1
sleep 1
touch client.output
exit 0
