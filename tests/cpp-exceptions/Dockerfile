FROM alpine as builder
RUN apk add build-base
WORKDIR /app
COPY ./basic-exceptions.cpp /app/
COPY ./libcxx-tests/ /app/

RUN for f in $(ls); \
    do g++ -g -fPIC -Wall -o ${f}.exe $f; \
    done;

FROM alpine

RUN apk add g++
COPY --from=builder /app/*.cpp.exe /app/
