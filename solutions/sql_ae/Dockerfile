FROM alpine:3.10 AS base-image

USER root
RUN apk add --no-cache bash sudo unixodbc-dev curl krb5-libs libstdc++ mbedtls

RUN mkdir -p /tmp/msodbcinstall && cd /tmp/msodbcinstall && \
curl --retry 5 --retry-max-time 120 -O https://download.microsoft.com/download/3/5/5/355d7943-a338-41a7-858d-53b259ea33f5/msodbcsql18_18.3.3.1-1_amd64.apk
RUN cd /tmp/msodbcinstall && sudo apk add --allow-untrusted $(ls)
RUN rm -rf /tmp/msodbcinstall
