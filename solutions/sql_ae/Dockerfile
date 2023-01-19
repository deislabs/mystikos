FROM alpine:3.10 AS base-image

USER root
RUN apk add --no-cache bash sudo unixodbc-dev curl krb5-libs libstdc++ mbedtls

RUN mkdir -p /tmp/msodbcinstall && cd /tmp/msodbcinstall && \
curl --retry 5 --retry-max-time 120 -O https://download.microsoft.com/download/e/4/e/e4e67866-dffd-428c-aac7-8d28ddafb39b/msodbcsql17_17.6.1.1-1_amd64.apk
RUN cd /tmp/msodbcinstall && sudo apk add --allow-untrusted $(ls)
RUN rm -rf /tmp/msodbcinstall
