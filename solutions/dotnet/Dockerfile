FROM alpine:3.10

RUN apk add --no-cache libstdc++ libintl

COPY ./HelloWorld /HelloWorld

WORKDIR /HelloWorld
ENTRYPOINT [ "build/HelloWorld" ]
