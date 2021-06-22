#!/bin/bash
pid=$(ps -eaf | grep /app/sockperf | grep root | awk '{ print $2 }')
if [ ! -z "${pid}" ]; then
    sudo kill -9 ${pid}
fi
