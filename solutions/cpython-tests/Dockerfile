FROM ubuntu:20.04
ARG CPYTHON_TAG=v3.8.11
WORKDIR /

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y build-essential libssl-dev libncurses5-dev libncursesw5-dev \
libreadline-dev libsqlite3-dev libgdbm-dev libdb5.3-dev libbz2-dev \
libexpat1-dev liblzma-dev libffi-dev git uuid-dev lsb-core wget

# Workaround broken crc32_z symbol on zlib 1.2.11 for Ubuntu 20.04
RUN wget https://github.com/madler/zlib/releases/download/v1.2.13/zlib-1.2.13.tar.gz && \
    tar xzf zlib-1.2.13.tar.gz && \
    cd zlib-1.2.13 && \
    make distclean && \
    ./configure && \
    make && \
    make install

RUN git clone --depth 1 --single-branch --branch $CPYTHON_TAG https://github.com/python/cpython
WORKDIR /cpython
# Apply patch to skip certain unit tests
COPY ./test_config_$CPYTHON_TAG/patch /cpython/
RUN git apply patch
# Apply patch to vfork, then build cpython
COPY vfork.diff .
RUN git apply vfork.diff --reject; ./configure --with-pydebug && make -j -s

WORKDIR /

#Copy test lists
COPY ./test_config_$CPYTHON_TAG/tests.* /

#workaround - Mystikos does not support Ubuntu's default shell dash
RUN ln -sf /bin/bash /bin/sh

#workaround - lsb_release invokes /usr/bin/python3. Ubuntu's default python executable is not PIE, not supported in Mystikos
RUN ln -sf /cpython/python /usr/bin/python3

# Copy Mystikos pdb
COPY ./mpdb.py /cpython/mpdb.py
