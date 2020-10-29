FROM ubuntu:18.04

ADD . /src
WORKDIR /src 

COPY ./build-libos.sh /build-libos.sh
RUN /bin/chmod 777 /build-libos.sh

RUN apt-get update
RUN apt-get -y install git

RUN mkdir /tmp/git
WORKDIR /tmp/git
RUN git clone --branch=mikbras.regions https://github.com/openenclave/openenclave.git 
RUN ./openenclave/scripts/ansible/install-ansible.sh 
RUN ansible-playbook ./openenclave/scripts/ansible/oe-contributors-acc-setup-no-driver.yml
RUN rm -rf /tmp/git

WORKDIR /
RUN apt-get -y install sudo

WORKDIR /src

CMD /build-libos.sh
