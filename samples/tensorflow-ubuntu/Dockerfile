FROM ubuntu:18.04 as ubuntu-build-base

# Build Python from source. The packaged Python executable is non-PIE.
# See issue https://bugs.launchpad.net/ubuntu/+source/python2.7/+bug/1452115
RUN apt update && \
    apt install -y git build-essential libffi-dev zlib1g-dev libssl-dev &&\
    rm -rf /var/lib/apt/lists/* &&\
    git clone https://github.com/python/cpython.git --branch 3.6 &&\
    cd cpython &&\
    ./configure && make -j 8 && make install &&\
    cd .. && rm -rf cpython && \
    apt remove -y git build-essential libffi-dev zlib1g-dev libssl-dev &&\
    apt -y autoremove &&\
    python3 --version


FROM ubuntu-build-base

# See http://bugs.python.org/issue19846
ENV LANG C.UTF-8

RUN apt update; apt install curl python3-pip -y

ENV PYTHONUNBUFFERED=1

RUN python3 -m pip --no-cache-dir install --upgrade \
    "pip<20.3" \
    setuptools

# Some TF tools expect a "python" binary
RUN ln -s $(which python3) /usr/local/bin/python

ARG TF_PACKAGE=tensorflow
ARG TF_PACKAGE_VERSION=
RUN python3 -m pip install --no-cache-dir tensorflow-cpu

RUN rm -rf /app;mkdir -p /app
WORKDIR /app
ADD mnist_convnet.py /app

# CMD ["/usr/local/bin/python3", "/app/mnist_convnet.py"]
