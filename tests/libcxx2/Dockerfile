FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    build-essential

COPY ./libcxx-tests/ /app/

ENV PREFIX_DIR=/app/llvm-project/libcxx/test

WORKDIR $PREFIX_DIR
RUN echo "Num tests = " $(find . -name \*pass.cpp | wc -l)

ENV TEST_DIR=$PREFIX_DIR

# Get a list of all subdirectories
RUN echo "Num directories = " && find . -type d | wc -l

# Go into every subdirectory and build cpp tests
RUN for dir in $(find . -type d); \
    do cd $dir ; \
    for f in $(ls | grep pass.cpp); \
        do g++ -std=c++17 -I $PREFIX_DIR/support -I $PREFIX_DIR/std -pthread -fPIC -Wall -o $( basename ${f}.exe) $f >> /app/log.log ; \
        done; \
    cd $TEST_DIR ; \
    done;

RUN find /app -name \*.exe > /ubuntu_built_exe.txt