FROM alpine:3.10 as builder
RUN apk add g++ curl-dev
WORKDIR /
COPY curl.c /

RUN g++ -g -fPIC -Wall -o /curl /curl.c -lcurl

FROM alpine:3.10
RUN apk add curl
COPY --from=builder /curl /curl
