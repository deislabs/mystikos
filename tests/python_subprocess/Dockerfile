FROM ubuntu:18.04

RUN apt update && apt install -y wget &&\
    wget -q https://repo.continuum.io/miniconda/Miniconda3-py39_4.9.2-Linux-x86_64.sh &&\
    chmod 755 Miniconda3-py39_4.9.2-Linux-x86_64.sh &&\
    ./Miniconda3-py39_4.9.2-Linux-x86_64.sh -b -p /miniconda &&\
    /miniconda/bin/python3 --version

WORKDIR /app
COPY ./test_subprocess.py .

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/miniconda/bin/python3", "/app/test_subprocess.py"]
