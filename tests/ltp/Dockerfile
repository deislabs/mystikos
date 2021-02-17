FROM alpine:3.12.3

RUN apk add bash build-base automake \
    autoconf linux-headers glib bison flex gawk xz 

RUN mkdir /ltp
COPY ltp/ /ltp/
COPY buildltp.sh /

WORKDIR /

RUN ["bash", "/buildltp.sh"]

