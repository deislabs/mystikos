FROM mystikos.azurecr.io/mystikos-bionic:latest

ADD appdir/bin/hello /appdir/bin/hello
ADD config.json config.json

RUN openssl genrsa -out private.pem -3 3072
RUN ./opt/mystikos/bin/myst package-sgx appdir private.pem config.json

WORKDIR /

CMD [ "./myst/bin/hello", "red", "green", "blue" ]
