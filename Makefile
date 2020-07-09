.PHONY: openenclave

BUILD_DIR=$(CURDIR)/build

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

openenclave: openenclave/build/Makefile
	$(MAKE) -C openenclave/build

openenclave/build/Makefile:
	mkdir openenclave/build
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
