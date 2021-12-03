ARG BASE_IMAGE=python:3.9-buster
ARG PYTORCH_VERSION=v1.10.0

FROM ${BASE_IMAGE} as test
RUN pip3 install pytest expecttest hypothesis && \
    pip3 install torch==1.10.0+cpu torchvision==0.11.1+cpu torchaudio==0.10.0+cpu -f https://download.pytorch.org/whl/cpu/torch_stable.html

WORKDIR /workspace
RUN git clone -b ${PYTORCH_VERSION} https://github.com/pytorch/pytorch.git --single-branch --depth 1
WORKDIR /workspace/pytorch
