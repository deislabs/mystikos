FROM python:3.9-slim

WORKDIR /app

RUN apt update && apt install -y git
# Checkout a stable build of Flask as of Sept. 2021
RUN git clone https://github.com/pallets/flask && cd flask && git checkout 6f852d0d22a9be486f3881d500ae83292a76cd46

WORKDIR /app/flask

RUN python -m pip install --upgrade pip setuptools &&\
    # Install Flask dev dependency
    pip install -r requirements/dev.txt && pip install -e . && pre-commit install &&\
    # Install a version of Blinker that is compatible with Python3.9
    python -m pip install git+https://github.com/jek/blinker.git@904d8d3803e84257c08526e9047474215aa1c976

ENV PYTHONUNBUFFERED=1

CMD ["/bin/bash"]
# CMD ["/usr/local/bin/pytest"]
