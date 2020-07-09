.PHONY: openenclave

BUILD_DIR=${CURDIR}/build

all: submodules openenclave

##==============================================================================
##
## submodules:
##
##==============================================================================

submodules:
	git submodule update --recursive --init --progress

##==============================================================================
##
## openenclave:
##
##==============================================================================

OPENENCLAVE_INSTALL_PREFIX=$(BUILD_DIR)

openenclave: configure_oe build_oe

configure_oe: openenclave/build/Makefile

openenclave/build/Makefile:
	rm -rf openenclave/build
	mkdir -p openenclave/build
	( cd openenclave/build; cmake -DUSE_DEBUG_MALLOC=1 -DHAS_QUOTE_PROVIDER=OFF -DCMAKE_INSTALL_PREFIX=$(OPENENCLAVE_INSTALL_PREFIX) .. )

build_oe:
	$(MAKE) -C openenclave/build install
	$(MAKE) -f oeenclave.mak

CLEAN += openenclave/build

##==============================================================================
##
## distclean:
##
##==============================================================================

CLEAN += $(BUILD_DIR)

distclean:
	rm -rf $(CLEAN)
