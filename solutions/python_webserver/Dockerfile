FROM ubuntu:20.04

# Install Python with miniconda. The Ubuntu Python package is non-PIE.
# See issue https://bugs.launchpad.net/ubuntu/+source/python2.7/+bug/1452115
RUN apt update && \
    apt install -y wget &&\
    wget -q https://repo.continuum.io/miniconda/Miniconda3-py38_4.8.2-Linux-x86_64.sh &&\
    chmod 755 Miniconda3-py38_4.8.2-Linux-x86_64.sh &&\
    ./Miniconda3-py38_4.8.2-Linux-x86_64.sh -b -p /miniconda &&\
    /miniconda/bin/pip install numpy==1.20.3 &&\
    /miniconda/bin/python3 --version

WORKDIR /app
COPY ./hello_server.py .

ENV PYTHONUNBUFFERED=1

CMD ["/miniconda/bin/python3", "/app/hello_server.py"]
