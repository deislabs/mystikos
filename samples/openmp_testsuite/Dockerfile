ARG IMAGE_FLAVOR=alpine
ARG IMAGE_VERSION=3.8

FROM ${IMAGE_FLAVOR}:${IMAGE_VERSION} AS repo
RUN wget -q https://ftp.gnu.org/gnu/gcc/gcc-7.5.0/gcc-7.5.0.tar.gz && \
    tar -xzf gcc-7.5.0.tar.gz && \
    rm -f gcc-7.5.0.tar.gz

FROM ${IMAGE_FLAVOR}:${IMAGE_VERSION}
RUN apk add --quiet --no-cache bash build-base dejagnu isl-dev make mpc1-dev mpfr-dev texinfo zlib-dev
COPY --from=repo /gcc-7.5.0/libgomp/testsuite /gcc-7.5.0/libgomp/testsuite
WORKDIR /gcc-7.5.0/libgomp/testsuite
COPY tests.mak .
RUN make -f tests.mak

CMD ["/bin/bash"]
