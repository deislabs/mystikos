DRIVER=sgx_linux_x64_driver_1.35.bin

DRIVER_URL=https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server

all:
	echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
	wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
	echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
	wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
	sudo apt update
	sudo apt install -y dkms libssl-dev cryptsetup-bin curl libcurl4-openssl-dev clang-8 clang-format-8 pkg-config python-pip
	sudo apt install -y libsgx-enclave-common libsgx-quote-ex  libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client
	pip install cmake && sudo find / -name cmake*
	sudo apt install -y docker.ce && sudo chmod 666 /var/run/docker.sock
	test -e /dev/sgx || $(MAKE) install_sgx_driver

install_sgx_driver:
	wget $(DRIVER_URL)/$(DRIVER)
	sudo bash ./$(DRIVER)
clean:
	rm -f $(DRIVER)

distclean: clean
