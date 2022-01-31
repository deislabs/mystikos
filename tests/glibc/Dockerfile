FROM ubuntu:18.04 as glibc-builder

RUN apt-get update && apt-get install -y \
    build-essential bison git gawk python3

COPY build .
COPY runtests .

COPY tests.all .

RUN sed -i 's/\/glibc\/build\///g' tests.all && cat tests.all

# build all the tests in tests.all
# this method was chosen to avoid the tests in tests.removed 
# since they have problems running in a container and freeze
RUN for t in $(cat tests.all); do \
 printf "\n\n\n\n"; echo $t; printf "\n\n\n\n" ; \
 make test t=$t;  printf $t; done
