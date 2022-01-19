#!/bin/bash
pid=$(ps -eaf | grep /app/webapp | grep -v grep | awk '{ print $2 }')
if [ ! -z "${pid}" ]; then
    sudo kill -9 ${pid}
fi
