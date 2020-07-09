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

OPENENCLAVE_INSTALL_PREFIX=$(BUILD_DIR)/openenclave

openenclave: openenclave/build/Makefile $(OPENENCLAVE_INSTALL_PREFIX)

$(OPENENCLAVE_INSTALL_PREFIX):
	$(MAKE) -C openenclave/build
	$(MAKE) -C openenclave/build install

openenclave/build/Makefile:
	mkdir -p openenclave/build
	( cd openenclave/build; cmake -DUSE_DEBUG_MALLOC=1 -DHAS_QUOTE_PROVIDER=OFF -DCMAKE_INSTALL_PREFIX=$(OPENENCLAVE_INSTALL_PREFIX) .. )

CLEAN += openenclave/build

##==============================================================================
##
## distclean:
##
##==============================================================================

CLEAN += $(BUILD_DIR)

distclean:
	rm -rf $(CLEAN)
