ARG IMAGE_FLAVOR
ARG IMAGE_VERSION
FROM ${IMAGE_FLAVOR}:${IMAGE_VERSION}

ARG GCC_VERSION

RUN apk add --quiet --no-cache bash build-base dejagnu isl-dev make mpc1-dev mpfr-dev texinfo zlib-dev
RUN wget -q https://ftp.gnu.org/gnu/gcc/gcc-${GCC_VERSION}/gcc-${GCC_VERSION}.tar.gz && \
    tar -xzf gcc-${GCC_VERSION}.tar.gz && \
    rm -f gcc-${GCC_VERSION}.tar.gz

RUN echo '----GCC compiling----'
WORKDIR /gcc-${GCC_VERSION}/libgomp/testsuite
COPY tests.mak .
RUN make -f tests.mak

CMD ["/bin/bash"]
