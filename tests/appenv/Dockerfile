FROM alpine:3.13.4

RUN apk update && apk upgrade \
    && apk add build-base

ENV VAR1=var1
ENV VAR2=$VAR1
ENV PATH=$PATH:/dummy/path

RUN mkdir -p /app/foo

WORKDIR /app/foo

ADD printvars.c .

RUN gcc -o printvars printvars.c
