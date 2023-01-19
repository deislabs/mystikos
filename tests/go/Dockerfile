FROM golang:alpine

RUN mkdir /app

COPY src/hello.go /app

RUN apk add build-base

RUN go install -buildmode=shared std

WORKDIR /app

RUN go build -linkshared hello.go

# Clean up so rootfs will be much smaller
RUN apk del build-base
RUN rm -rf /root/.cache
RUN rm -rf `find / -name '*.a'`
RUN rm -rf /usr/local/go/src
RUN rm -rf /usr/local/go/test
RUN rm -rf /usr/local/go/bin
RUN rm -rf /usr/local/go/pkg/tool
