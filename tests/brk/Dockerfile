FROM alpine:3.13.4

RUN apk update
RUN apk upgrade
RUN apk add build-base

RUN mkdir /app

COPY brk.cpp /app

RUN g++ -o /app/brk /app/brk.cpp
