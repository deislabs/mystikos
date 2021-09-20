FROM python:3.9-slim
ARG TAG
ARG PACKAGES

RUN apt update && apt install -y git

WORKDIR /
RUN git clone -b ${TAG} https://github.com/Azure/azure-sdk-for-python --single-branch --depth 1
ADD install-dev-requirements.sh ${PACKAGES} /
RUN chmod +x /install-dev-requirements.sh \
    && /install-dev-requirements.sh
