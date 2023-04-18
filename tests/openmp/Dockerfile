FROM ubuntu:20.04

RUN apt-get update && apt-get install -y gcc libgomp1

RUN rm -rf /app;mkdir -p /app
ADD omp_dlopen.c /app

RUN cd /app && \
    gcc -o omp-dlopen -Wall -g omp_dlopen.c -ldl

CMD ["/bin/bash"]
