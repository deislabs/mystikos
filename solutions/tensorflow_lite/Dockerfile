FROM python:3.6-slim-buster

RUN apt-get update && apt-get install -y \
    curl gnupg2

RUN echo "deb https://packages.cloud.google.com/apt coral-edgetpu-stable main" | tee /etc/apt/sources.list.d/coral-edgetpu.list
RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
apt-get update && \
apt-get install -y python3-tflite-runtime

RUN python3 -m pip install pillow numpy

# Create a working directory
RUN mkdir /app
WORKDIR /app
ADD label_image.py /app

# Get photo
RUN curl -L --retry 3 https://raw.githubusercontent.com/tensorflow/tensorflow/master/tensorflow/lite/examples/label_image/testdata/grace_hopper.bmp > /tmp/grace_hopper.bmp
# Get model
RUN curl -L --retry 3 https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_2018_02_22/mobilenet_v1_1.0_224.tgz | tar xzv -C /tmp
# Get labels
RUN curl -L --retry 3 https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_1.0_224_frozen.tgz  | tar xzv -C /tmp  mobilenet_v1_1.0_224/labels.txt

RUN mv /tmp/mobilenet_v1_1.0_224/labels.txt /tmp/

#numpy installed with python3-tflite-runtime is broken. Remove it to use pip-intalled version
RUN rm -fr /usr/lib/python3/dist-packages/numpy

ENV PYTHONPATH='/usr/lib/python3/dist-packages'

CMD ["/bin/bash"]
