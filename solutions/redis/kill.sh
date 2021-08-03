#!/bin/bash
pid=$(ps -eaf | grep redis-server | grep -v grep | awk '{ print $2 }')
ps -eaf | grep redis
if [ ! -z "${pid}" ]; then
    sudo kill -9 ${pid}
    echo "killed"
    exit 0
fi
echo "nothing to kill"
