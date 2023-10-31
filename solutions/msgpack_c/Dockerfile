# stage 1 build
FROM alpine:3.10 AS base-image

RUN apk add --no-cache curl build-base bash git unzip boost-dev cmake zlib-dev

# Ubuntu configuration
# FROM ubuntu:18.04 AS base-image

# RUN apt-get install -y -q cmake curl build-essential bash git unzip libboost-dev libboost-chrono-dev libboost-system-dev libboost-timer-dev lib32z1-dev

RUN rm -rf /app;mkdir -p /app
	
WORKDIR /app

# download and compile googletest 1.7.0 (official supported version)
RUN curl -L  https://github.com/google/googletest/archive/release-1.7.0.zip -o googletest.zip
RUN unzip googletest.zip
RUN cd googletest-release-1.7.0; \
    mkdir build;cd build;cmake ..;make; \
    mv *.a /usr/lib;cp -r ../include/gtest /usr/include

# clone and compile msgpack repo
RUN git clone --depth 1 --single-branch --branch cpp-3.3.0 https://github.com/msgpack/msgpack-c.git msgpack
RUN mkdir -p /app/msgpack/build; \
    cd /app/msgpack/build;cmake ..;make
RUN mkdir -p /app/tests
# filter and copy all executable test binaries to another directory
RUN cd /app/msgpack/build/test; \
    cp $(find \( ! -name "*.cmake" ! -name "Makefile" \) -maxdepth 1 -type f) /app/tests

# stage2 get binaries
FROM alpine:3.10

RUN apk add --no-cache zlib-dev libgcc libstdc++

RUN rm -rf /tests;mkdir -p /tests

COPY --from=base-image /app/tests /tests

COPY --from=base-image /app/msgpack/build/libmsgpackc.so* /lib/

WORKDIR /app
