FROM ubuntu:18.04
ARG CPYTHON_VERSION=v3.8.11
WORKDIR /

RUN apt update && apt install -y build-essential libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev \
        libreadline-dev libsqlite3-dev libgdbm-dev libdb5.3-dev libbz2-dev \
        libexpat1-dev liblzma-dev libffi-dev git

RUN git clone -b $CPYTHON_VERSION https://github.com/python/cpython
WORKDIR /cpython
RUN ./configure --with-pydebug && make -j -s

WORKDIR /

#Copy test lists
COPY tests.* /

RUN ln -sf /bin/bash /bin/sh
