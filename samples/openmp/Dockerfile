FROM alpine:3.10

RUN apk add --no-cache \
    g++ libgomp

RUN rm -rf /app;mkdir -p /app
ADD openmp-test.c /app

RUN cd /app && \
    g++ -o openmp-test -fopenmp openmp-test.c

CMD [/app/openmp-test]