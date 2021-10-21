DRIVER=sgx_linux_x64_driver_1.35.bin

DRIVER_URL=https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server
UBUNTU_RELEASE=$(shell lsb_release -c | awk '{print $$2}')

all:
	test -e package-installed || $(MAKE) packages
	test -e /dev/sgx || $(MAKE) install_sgx_driver

wait_dpkg:
	while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done

package_repo:
	echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
	wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
	echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
	wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
	sudo apt update

packages: package_repo
	$(MAKE) wait_dpkg
	sudo apt install -y gdb dkms libssl-dev cryptsetup-bin curl libcurl4-openssl-dev clang-10 clang-format-10 pkg-config
ifeq ("$(UBUNTU_RELEASE)", "focal")
	sudo apt install -y python3-pip
	if [ ! -f /usr/bin/pip ]; then sudo ln -s /usr/bin/pip3 /usr/bin/pip; fi
else
	sudo apt install -y python-pip
endif
	$(MAKE) wait_dpkg
	sudo apt install -y libsgx-enclave-common libsgx-quote-ex  libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client
	pip install cmake && sudo ln -f -s $(HOME)/.local/bin/cmake /usr/bin/cmake
	touch package-installed

install_sgx_driver:
	wget $(DRIVER_URL)/$(DRIVER)
	sudo bash ./$(DRIVER)

clean:
	rm -f $(DRIVER) package-installed

distclean: clean
