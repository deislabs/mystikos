ARG IMAGE_FLAVOR
ARG IMAGE_VERSION
FROM ${IMAGE_FLAVOR}:${IMAGE_VERSION}

ARG GCC_VERSION 

RUN apk add --quiet --no-cache bash build-base dejagnu isl-dev make mpc1-dev mpfr-dev texinfo zlib-dev
RUN wget -q https://ftp.gnu.org/gnu/gcc/gcc-${GCC_VERSION}/gcc-${GCC_VERSION}.tar.gz && \
    tar -xzf gcc-${GCC_VERSION}.tar.gz && \
    rm -f gcc-${GCC_VERSION}.tar.gz

RUN echo '----GCC configure----'
WORKDIR /gcc-${GCC_VERSION}
RUN ./configure \
        --build=$(uname -m)-alpine-linux-musl \
        --target=$(uname -m)-alpine-linux-musl \
        --disable-fixed-point \
        --disable-libmpx \
        --disable-libmudflap \
        --disable-libsanitizer \
        --disable-libssp \
        --disable-libstdcxx-pch \
        --disable-multilib \
        --disable-nls \
        --disable-symvers \
        --disable-werror \
        --enable-languages=c,c++ \
        --enable-shared \
        --enable-threads \
        --enable-tls \
        --with-system-zlib

RUN echo '----GCC compiling----'
RUN make -j $(nproc)

CMD ["/bin/bash"]