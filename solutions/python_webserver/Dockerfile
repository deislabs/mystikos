FROM ubuntu:18.04

# Build Python from source. The packaged Python executable is non-PIE.
# See issue https://bugs.launchpad.net/ubuntu/+source/python2.7/+bug/1452115
RUN apt update && \
    apt install -y git build-essential libssl-dev libffi-dev zlib1g-dev  &&\
    rm -rf /var/lib/apt/lists/* &&\
    git clone https://github.com/python/cpython.git --branch 3.6 &&\
    cd cpython &&\
    ./configure && make -j 4 && make install &&\
    cd .. && rm -rf cpython &&\
    apt remove -y git build-essential libffi-dev zlib1g-dev &&\
    apt -y autoremove &&\
    pip3 install numpy &&\
    python3 --version

WORKDIR /app
COPY ./hello_server.py .

ENV PYTHONUNBUFFERED=1

CMD ["python3", "/app/hello_server.py"]
