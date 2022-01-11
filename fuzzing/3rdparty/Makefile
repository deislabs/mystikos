TOP=$(abspath $(CURDIR)/../..)
BUILDDIR=${TOP}/build
URL=https://github.com/intel/linux-sgx.git
BRANCH=master

LINUX_SGX_SDK_SRC = $(CURDIR)/linux-sgx
LINUX_SGX_SDK_BUILD = $(CURDIR)/linux-sgx/build

all: 
	$(MAKE) linux-sgx
	$(MAKE) make-linux-sgx

linux-sgx:
	( cd $(LINUX_SGX_SDK_SRC); git clone $(URL) -b $(BRANCH) )

make-linux-sgx: 
	$(MAKE) -C $(LINUX_SGX_SDK_SRC) preparation
	$(MAKE) -C $(LINUX_SGX_SDK_SRC) psw DEBUG=1 -j6

clean:
	rm -rf $(LINUX_SGX_SDK_SRC)

distclean: clean
