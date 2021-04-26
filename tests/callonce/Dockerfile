FROM ubuntu:18.04

RUN apt-get update && apt-get install -y g++

RUN rm -rf /app;mkdir -p /app
ADD callonce.cc /app

RUN cd /app && \
    g++ -g -fPIC -Wall -o call-once -pthread callonce.cc

CMD ["/bin/bash"]
#CMD [/app/call-once]
