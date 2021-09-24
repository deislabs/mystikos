FROM python:3.9-slim

RUN pip3 install numpy pandas pytest hypothesis &&\
    ln -sf /bin/bash /bin/sh

WORKDIR /app
COPY ./numpy_core_tests/numpy_app.py .
COPY ./pandas_tests/pandas_app.py .

ENV PYTHONUNBUFFERED=1
