ARG IMAGE_FLAVOR=alpine
ARG IMAGE_VERSION=latest

FROM ${IMAGE_FLAVOR}:${IMAGE_VERSION} AS builder
RUN wget -q https://ftp.gnu.org/gnu/gcc/gcc-7.5.0/gcc-7.5.0.tar.gz && \
    tar -xzf gcc-7.5.0.tar.gz && \
    rm -f gcc-7.5.0.tar.gz
RUN apk add --quiet --no-cache bash build-base dejagnu isl-dev make mpc1-dev mpfr-dev texinfo zlib-dev
WORKDIR /gcc-7.5.0/libgomp/testsuite
COPY tests.mak .
RUN make -f tests.mak

FROM ${IMAGE_FLAVOR}:${IMAGE_VERSION}
RUN apk add --quiet --no-cache bash build-base
COPY --from=builder /gcc-7.5.0/libgomp/testsuite/libgomp.c /gcc-7.5.0/libgomp/testsuite/libgomp.c

CMD ["/bin/bash"]
