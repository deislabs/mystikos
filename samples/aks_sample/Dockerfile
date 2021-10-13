FROM ubuntu:18.04
ARG PSW_VERSION
ARG MYST_RELEASE_VERSION

ADD appdir/bin/hello /appdir/bin/hello
ADD config.json config.json

RUN if [ -z "$PSW_VERSION" ]; then echo "Please set PSW_VERSION (e.g. 2.15.100)." >&2; exit 1; fi
RUN if [ -z "$MYST_RELEASE_VERSION" ]; then echo "Please set MYST_RELEASE_VERSION (e.g. 0.5.0)." >&2; exit 1; fi

RUN apt-get update && apt-get install -y \
    wget \
    gnupg

# Get the mystikos release tarball
RUN wget https://github.com/deislabs/mystikos/releases/download/v${MYST_RELEASE_VERSION}/mystikos-${MYST_RELEASE_VERSION}-x86_64.tar.gz \
    && tar -xvf mystikos-${MYST_RELEASE_VERSION}-x86_64.tar.gz

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
    az-dcap-client

RUN openssl genrsa -out private.pem -3 3072
RUN ./mystikos/bin/myst package-sgx appdir private.pem config.json

WORKDIR /
CMD [ "./myst/bin/hello", "red", "green", "blue" ]
