# stage 1 build
FROM alpine:3.12.3 AS base-image

RUN apk add --no-cache bash build-base cmake git openssl-dev linux-headers


WORKDIR /src

# clone and build
RUN git clone --recursive https://github.com/corvusoft/restbed.git restbed
RUN mkdir -p restbed/build; cd restbed/build; \
    cmake -DBUILD_SSL=NO ..; make install;
# filter all test executables and put them to /tests folder
RUN mkdir -p /tests;cd restbed/build/test;\
    cp $(find \( ! -name "*.cmake" ! -name "Makefile" \) -maxdepth 2 -type f) /tests

# stage2 get binaries
FROM alpine:3.12.3

RUN apk add --no-cache zlib-dev libgcc libstdc++

RUN rm -rf /tests;mkdir -p /tests

COPY --from=base-image /tests /tests

WORKDIR /tests

