FROM ubuntu:20.04 as builder

RUN apt-get update && apt-get install -y wget gcc

# Using these as links so that this Dockerfile is stand-alone
RUN wget https://raw.githubusercontent.com/deislabs/mystikos/main/samples/docker_aks/hello.c
RUN wget https://raw.githubusercontent.com/deislabs/mystikos/main/samples/docker_aks/config.json

RUN gcc -fPIC -o hello hello.c

FROM mystikos.azurecr.io/mystikos-focal:latest

COPY --from=builder /hello /appdir/bin/hello
COPY --from=builder /config.json /config.json

RUN openssl genrsa -out private.pem -3 3072
RUN ./opt/mystikos/bin/myst package-sgx appdir private.pem config.json

WORKDIR /

CMD [ "./myst/bin/hello", "red", "green", "blue" ]
