#!/bin/bash

if [[ $1 == "FlightFinder" ]]; then
    TERM="/built/FlightFinder/FlightFinder.Server.dll"
elif [[ $1 == "Todo" ]]; then
    TERM="/built/TodoApi/TodoApi"
elif [[ $1 == "Podcast" ]]; then
    TERM="/built/dotnet-podcasts/Podcast.API"
else
    echo "Invalid argument: $1"
fi

pid=$(ps -eaf | grep $TERM | grep -v grep | awk '{ print $2 }')
if [ ! -z "${pid}" ]; then
    sudo kill -9 ${pid}
fi
