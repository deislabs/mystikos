FROM python:3-alpine

RUN apk add build-base py3-pip

WORKDIR /app
COPY ./hello_world.py /app

# ATTN: this takes a long time. Optimize!
RUN /usr/local/bin/pip install numpy

ENTRYPOINT ["python3", "hello_world.py"]
