TOP=$(abspath $(CURDIR)/../..)
include $(TOP)/defs.mak

INTEL_SGX_SDK=https://download.01.org/intel-sgx/sgx-linux/2.15/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.15.100.3.bin
INTEL_SGX_SDK_PACKAGE=sgx_linux_x64_sdk_2.15.100.3.bin
OE_LLVM=https://github.com/openenclave/openenclave-security/releases/download/v2.0/oe-llvm-2.0.zip
OE_LLVM_PACKAGE=oe-llvm-2.0.zip

all:
	test -e $(BUILDDIR) || $(MAKE) create_build_dir
	test -e package-installed || $(MAKE) packages
	test -e /opt/intel/sgxsdk || $(MAKE) install_sgx_sdk
	test -e $(BUILDDIR)/oe-llvm-2.0 || $(MAKE) get_oellvm

create_build_dir:
	mkdir -p $(BUILDDIR)

packages:
	sudo apt install -y build-essential ocaml ocamlbuild automake autoconf libtool wget
	sudo apt install -y libssl-dev perl libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper reprepro unzip
	touch package-installed

install_sgx_sdk:
	(cd $(BUILDDIR); wget $(INTEL_SGX_SDK))
	(cd $(BUILDDIR); chmod +x ./$(INTEL_SGX_SDK_PACKAGE))
	(cd $(BUILDDIR); sudo bash $(CURDIR)/install-sgxsdk.sh $(BUILDDIR)/$(INTEL_SGX_SDK_PACKAGE))

get_oellvm:
	(cd $(BUILDDIR); wget $(OE_LLVM))
	(cd $(BUILDDIR); unzip $(OE_LLVM_PACKAGE))

clean:
	rm -f package-installed

distclean: clean
