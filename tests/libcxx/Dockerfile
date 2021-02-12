FROM alpine as builder
RUN apk add build-base
COPY ./libcxx-tests/ /app/

ENV PREFIX_DIR=/app/llvm-project/libcxx/test
COPY builttests.txt $PREFIX_DIR

WORKDIR $PREFIX_DIR
RUN echo "Num tests = " $(find . -name \*pass.cpp | wc -l)

ENV TEST_DIR=$PREFIX_DIR

# Get a list of all subdirectories
RUN echo "Num directories = " && find . -type d | wc -l

# Go into every subdirectory and build cpp tests
RUN for dir in $(find . -type d); \
    do cd $dir ; \
    for f in $(ls | grep pass.cpp); \
        do g++ -I $PREFIX_DIR/support -fPIC -Wall -o $( basename ${f}.exe) $f ; \
        done; \
    cd $TEST_DIR ; \
    done;

FROM alpine

RUN apk add g++

COPY --from=builder /app /tmpdir
RUN mkdir /app

RUN find /tmpdir -name \*.exe -exec cp {} /app \;
RUN find /app -name \*.exe > /alpine_passed_exe.txt
RUN rm -rf tmpdir 