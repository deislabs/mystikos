FROM alpine:3.7 as builder

RUN apk update && apk upgrade
RUN apk add build-base perl make automake autoconf m4 git libexecinfo-dev

WORKDIR /app

RUN git clone -b sagoel.mystikos --single-branch  https://github.com/salsal97/sockperf.git

RUN cd sockperf && ./autogen.sh \
    && ./configure --enable-test \
    && make \
    && make install

FROM alpine:3.7

RUN apk update && apk upgrade
RUN apk add build-base libexecinfo-dev

RUN mkdir /app

COPY --from=builder /app/sockperf/sockperf /app
