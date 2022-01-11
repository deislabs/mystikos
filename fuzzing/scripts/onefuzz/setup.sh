#!/bin/bash
# This script will be invoked by onefuzz service inside the context of VM deployed for fuzzing.

set -ex

echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

sudo apt-get update
sudo apt-get -y install llvm clang clang-tools libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client

# Copy the debug version of libsgx_enclave_common.so to /usr/lib/x86_64-linux-gnu/
[[ -f "/usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1" ]] && sudo rm /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so*
sudo cp ${ONEFUZZ_TARGET_SETUP_PATH}/libsgx_enclave_common.so /usr/lib/x86_64-linux-gnu/
sudo ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1
