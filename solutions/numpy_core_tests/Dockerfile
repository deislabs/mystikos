FROM python:3.9-slim

RUN pip3 install numpy pytest hypothesis==6.52.1 &&\
    ln -sf /bin/bash /bin/sh

WORKDIR /app
COPY ./app.py .

ENV PYTHONUNBUFFERED=1

CMD ["/usr/local/bin/python3", "/app/app.py"]
