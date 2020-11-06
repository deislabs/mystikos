FROM ubuntu:18.04
ARG PSW_VERSION

ADD openlibos.tar.gz /
ADD rootfs /
RUN if [ -z "$PSW_VERSION" ]; then echo "Please set PSW_VERSION (e.g. 2.11)." >&2; exit 1; fi
RUN apt-get update && apt-get install -y \
    wget \
    gnupg

# Use the APT preference file to pin sgx packages to specific versions
# Reference https://manpages.debian.org/buster/apt/apt_preferences.5.en.html
# Download the pref file from https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/
# Assuming file name to follow *sgx_<PSW_VERSION>_bionic_custom_version.cfg convention
RUN ["/bin/bash", "-c", "wget -r -l1 --no-parent -nd -A *sgx_$(echo ${PSW_VERSION//./_})_bionic_custom_version.cfg https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/"]
RUN ["/bin/bash", "-c", "mv *sgx_$(echo ${PSW_VERSION//./_})_bionic_custom_version.cfg /etc/apt/preferences.d/intel-sgx.pref"]

# Add the repository to sources, and add the key to the list of
# trusted keys used by the apt to authenticate packages
RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" | tee /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
# Add Microsoft repo for az-dcap-client
RUN echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | tee /etc/apt/sources.list.d/msprod.list \
    && wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

RUN apt-get update && apt-get install -y \
    libsgx-enclave-common \
    libsgx-dcap-ql \
    libsgx-quote-ex \
    az-dcap-client \
    open-enclave

WORKDIR /
CMD [ "/openlibos/bin/libos", "exec-sgx", "/rootfs", "/bin/hello", "red", "green", "blue" ]
