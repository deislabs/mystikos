FROM ubuntu:18.04
RUN apt update && apt install -y git build-essential autotools-dev zlib1g-dev

RUN git clone https://github.com/python/cpython.git --branch 3.6
WORKDIR /cpython
RUN ./configure && make -j 4 && make install && which python3

WORKDIR /app
COPY ./hello_server.py .

ENV PYTHONUNBUFFERED=1
CMD ["python3", "/app/hello_server.py"]
