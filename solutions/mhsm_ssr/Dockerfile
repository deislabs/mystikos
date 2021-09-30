FROM ubuntu:18.04
RUN apt update && apt install -y libcurl4-openssl-dev libmbedtls-dev
COPY test_ssr /bin/
COPY libmhsm_ssr.so /lib/
