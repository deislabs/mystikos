#!/bin/bash
pid=$(ps -eaf | grep "${1}\|${2}" | grep ext2rootfs | awk '{ print $2 }')
if [ ! -z "${pid}" ]; then
    kill -9 ${pid}
fi
