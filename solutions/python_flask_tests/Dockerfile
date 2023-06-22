FROM python:3.9-slim-bullseye
# Pin to older version of image as newer image comes with newer libstdc++ and libc versions, which use elf/loader features musl does not support.

WORKDIR /app

RUN apt update && apt install -y git
# Checkout Flask v2.3.2
RUN git clone https://github.com/pallets/flask && cd flask && git checkout f3b8f570545200c87465d18386f3fc9f2258307a

WORKDIR /app/flask

RUN python -m pip install --upgrade pip setuptools &&\
    # Install Flask dev dependency
    pip install -r requirements/dev.txt && pip install -e . && pre-commit install

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/local/bin/python", "/usr/local/bin/pytest"]
