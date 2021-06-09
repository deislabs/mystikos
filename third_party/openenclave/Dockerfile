FROM ubuntu:18.04

##
## Install git
##
RUN apt-get update
RUN apt-get -y install git

##
## checkout openenclave repository
##
RUN mkdir /work
WORKDIR /work
RUN git clone --recursive https://github.com/openenclave/openenclave -b mystikos.v4


##
## install ansible and run ansible-playbook
##
WORKDIR /work/openenclave
RUN ./scripts/ansible/install-ansible.sh
RUN ansible-playbook ./scripts/ansible/oe-contributors-acc-setup-no-driver.yml

##
## Build openenclave
##
RUN mkdir build
WORKDIR /work/openenclave/build
RUN cmake -DHAS_QUOTE_PROVIDER=OFF -DBUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=/work/install ..
RUN make
RUN make install
