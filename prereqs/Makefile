OS_NAME=$(shell lsb_release -c | sed 's/Codename\://g' | xargs)
OS_VERSION=$(shell lsb_release -r | sed 's/Release\://g' | xargs)

DRIVER=sgx_linux_x64_driver_1.35.bin
DRIVER_URL=https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server

PIP_INSTALL=python3-pip
PIP=pip3
ifeq ("$(OS_NAME)", "bionic")
PIP_INSTALL=python-pip
PIP=pip
endif

all:
	test -e package-installed || $(MAKE) packages
	test -e /dev/sgx || $(MAKE) install_sgx_driver

wait_dpkg:
	while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done

package_repo:
	echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(OS_NAME) main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
	wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
	echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/$(OS_VERSION)/prod $(OS_NAME) main" | sudo tee /etc/apt/sources.list.d/msprod.list
	wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
	sudo apt update

packages: package_repo
	$(MAKE) wait_dpkg
	sudo apt install -y libsgx-enclave-common libsgx-quote-ex libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client $(PIP_INSTALL)
	$(PIP) install cmake && sudo ln -f -s $(HOME)/.local/bin/cmake /usr/bin/cmake
	touch package-installed

install_sgx_driver:
ifeq ("$(OS_NAME)", "bionic")
	wget $(DRIVER_URL)/$(DRIVER)
	sudo bash ./$(DRIVER)
endif

clean:
	rm -f $(DRIVER) package-installed

distclean: clean
