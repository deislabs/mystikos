TOP=$(abspath $(CURDIR)/../..)

BUILDDIR=${TOP}/build

OECACHE_DIR=$(HOME)/.myst/oecache

all: $(BUILDDIR)/include/openenclave

ifdef MYST_USE_OECACHE
OECACHE_CHECK=$(wildcard $(OECACHE_DIR)/__oe__/include/openenclave/enclave.h)
endif

$(BUILDDIR)/include/openenclave:
ifeq ($(OECACHE_CHECK),)
	$(MAKE) submodules
	$(MAKE) openenclave
else
	$(MAKE) fetch_oecache
endif

fetch_oecache: $(TOP)/build/openenclave $(TOP)/build/bin/myst-gdb

$(TOP)/build/openenclave:
	mkdir -p $(BUILDDIR)
	rm -rf $(BUILDDIR)/openenclave
	cp -r $(OECACHE_DIR)/__oe__ $(BUILDDIR)/openenclave

$(TOP)/build/bin/myst-gdb:
	mkdir -p $(BUILDDIR)/bin
	rm -f $(BUILDDIR)/bin/myst-gdb
	ln -s $(BUILDDIR)/openenclave/bin/oegdb $(BUILDDIR)/bin/myst-gdb

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

OPENENCLAVE_INSTALL_PREFIX=$(BUILDDIR)/openenclave

OPENENCLAVE_SRC = $(CURDIR)/openenclave

OPENENCLAVE_BUILD = $(CURDIR)/openenclave/build

.PHONY: openenclave

# Only install dependencies if $(OPENENCLAVE_BUILD) does not exit.
DEPENDENCY_TARGET = $(OPENENCLAVE_BUILD)/dependency_target

openenclave: $(DEPENDENCY_TARGET) configure_oe install_oe

$(DEPENDENCY_TARGET):
ifneq ($(MYST_IGNORE_PREREQS),1)
	sudo $(OPENENCLAVE_SRC)/scripts/ansible/install-ansible.sh
	sudo ansible-playbook $(OPENENCLAVE_SRC)/scripts/ansible/oe-contributors-acc-setup-no-driver.yml
endif
	mkdir -p $(OPENENCLAVE_BUILD)

configure_oe: $(OPENENCLAVE_BUILD)/Makefile

CMAKE_OPTS =

ifeq ($(MYST_RELEASE),1)
CMAKE_OPTS += -DCMAKE_BUILD_TYPE=Release
else
CMAKE_OPTS += -DUSE_DEBUG_MALLOC=1
endif

CMAKE_OPTS += -DHAS_QUOTE_PROVIDER=OFF
CMAKE_OPTS += -DBUILD_TESTS=OFF
CMAKE_OPTS += -DCMAKE_INSTALL_PREFIX=$(OPENENCLAVE_INSTALL_PREFIX)
CMAKE_OPTS += -DSGX_MAX_TCS=4096

$(OPENENCLAVE_BUILD)/Makefile:
	rm -rf $(OPENENCLAVE_BUILD)
	mkdir -p $(OPENENCLAVE_BUILD)
	touch $(DEPENDENCY_TARGET)
	( cd $(OPENENCLAVE_BUILD); cmake $(CMAKE_OPTS) .. )

install_oe:
	$(MAKE) -C $(OPENENCLAVE_BUILD) install
ifdef MYST_USE_OECACHE
	rm -rf $(OECACHE_DIR)
	$(MAKE) -C $(OPENENCLAVE_BUILD) install DESTDIR=$(OECACHE_DIR)
	mv $(OECACHE_DIR)/$(OPENENCLAVE_INSTALL_PREFIX) $(OECACHE_DIR)/__oe__
endif
	mkdir -p $(TOP)/build/bin
	rm -f $(TOP)/build/bin/myst-gdb
	ln -s $(TOP)/build/openenclave/bin/oegdb $(TOP)/build/bin/myst-gdb

##==============================================================================
##
## clean:
## distclean:
##
##==============================================================================

DISTCLEAN += $(BUILDDIR)
DISTCLEAN += $(OPENENCLAVE_BUILD)

clean:
	rm -rf $(TOP)/build/openenclave
	rm -f $(TOP)/build/bin/myst-gdb

distclean: clean
	rm -rf $(DISTCLEAN)

cleandeps:
	rm -f $(DEPENDENCY_TARGET)

tests:

force:
	rm -rf $(BUILDDIR)/include/openenclave
	$(MAKE)
