FROM ubuntu:20.04

RUN apt update && apt install -y curl gnupg2 &&\
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - &&\
    curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list &&\
    apt update && \
    apt install -y wget &&\
    ACCEPT_EULA=Y apt install -y msodbcsql17 &&\
    wget -q https://repo.continuum.io/miniconda/Miniconda3-py38_4.8.2-Linux-x86_64.sh &&\
    chmod 755 Miniconda3-py38_4.8.2-Linux-x86_64.sh &&\
    ./Miniconda3-py38_4.8.2-Linux-x86_64.sh -b -p /miniconda &&\
    /miniconda/bin/pip install numpy==1.20.3 logzero &&\
    /miniconda/bin/conda install -y -c miniconda pyodbc pandas pycrypto pycurl pyjwt &&\
    /miniconda/bin/python3 --version

WORKDIR /app
COPY ./app.py .

ENV PYTHONUNBUFFERED=1

CMD ["/miniconda/bin/python3", "/app/app.py"]
