FROM alpine:3.7 as builder

RUN apk update && apk upgrade
RUN apk add build-base perl make automake autoconf m4 git libexecinfo-dev

RUN git clone --single-branch --branch sockperf_v2 https://github.com/Mellanox/sockperf.git

WORKDIR /sockperf

RUN git checkout b3df070d564973c9d6a4a0e143de7703043c5713

COPY mystikos_changes.patch /sockperf
RUN git apply mystikos_changes.patch

RUN ./autogen.sh \
    && ./configure --enable-test \
    && make \
    && make install

FROM alpine:3.7

RUN apk update && apk upgrade
RUN apk add build-base libexecinfo-dev

RUN mkdir /app

COPY --from=builder /sockperf/sockperf /app
