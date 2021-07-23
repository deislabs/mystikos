#!/bin/bash
pid=$(ps -eaf | grep redis | grep -v grep | awk '{ print $2 }')
if [ ! -z "${pid}" ]; then
    sudo kill -9 ${pid}
fi
