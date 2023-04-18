FROM ubuntu:20.04

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
RUN CFLAGS="-I $PREFIX_DIR/support -I $PREFIX_DIR/std -I $PREFIX_DIR/../include -DTEST_HAS_SANITIZERS -D_LIBCPP_VERSION=11000" && \
    for dir in $(find . -type d); \
    do cd $dir ; \
    for f in $(ls | grep pass.cpp); \
       do echo "$dir/$f" ; \
       g++ -std=c++17 $CFLAGS $LDFLAGS -pthread -fPIC -o $f.exe $f >> ~/full.log 2>&1 ; \
       done; \
    cd $TEST_DIR ; \
    done;

RUN cat ~/full.log | grep "has not been declared" | grep "test/../include/" | cut -d: -f1 | sort -u >> ~/log

RUN find /app -name \*.exe > /ubuntu_built_exe.txt
