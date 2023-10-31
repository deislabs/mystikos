FROM ubuntu:20.04 as builder
ARG TAG=release/2.34/master

RUN apt-get update && apt-get install -y \
    build-essential bison git gawk python3

# checkout glibc
WORKDIR /
RUN git clone --depth 1 --single-branch --branch ${TAG} https://sourceware.org/git/glibc.git
WORKDIR /glibc
COPY patch.diff .
RUN git apply patch.diff

# configure the build
WORKDIR /glibc/build
RUN ../configure --prefix=/usr \
                 --disable-werror \
                 --enable-static-pie

# build glibc
RUN make -j

# Future enhancement after confirming stability
# FROM ubuntu:18.04
# COPY --from=builder /glibc/build .

COPY tests.all .

RUN sed -i 's/\/glibc\/build\///g' tests.all && cat tests.all

# build all the tests in tests.all
# this method was chosen to avoid the tests in tests.removed 
# since they have problems running in a container and freeze
RUN for t in $(cat tests.all); do \
 printf "\n\n\n\n"; echo $t; printf "\n\n\n\n" ; \
 make test t=$t;  printf $t; done
