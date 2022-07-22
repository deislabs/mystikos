ARG BASE_IMAGE=python:3.9-buster

FROM ${BASE_IMAGE} as test
ARG TAG=v1.10.0
ARG PYTORCH_VERSION=${TAG}

RUN pip3 install pytest expecttest hypothesis==6.52.1 && \
    pip3 install torch==1.10.0+cpu torchvision==0.11.1+cpu torchaudio==0.10.0+cpu -f https://download.pytorch.org/whl/cpu/torch_stable.html

WORKDIR /workspace
RUN git clone -b ${TAG} https://github.com/pytorch/pytorch.git --single-branch --depth 1
WORKDIR /workspace/pytorch
