.NOTPARALLEL:

TOP=$(abspath $(CURDIR)/../..)

BUILDDIR=${TOP}/build

URL=https://github.com/openenclave/openenclave

BRANCH=mystikos.v4

# get the hash of the remote github repository (for the given branch)
HASH=$(shell git ls-remote $(URL) -b $(BRANCH) | cut -f1 )

CACHE_DIR=$(HOME)/.mystikos/cache/openenclave

CACHE=$(CACHE_DIR)/$(HASH)

all: $(BUILDDIR)/include/openenclave

ifdef MYST_USE_BUILD_CACHE
CACHE_CHECK=$(wildcard $(CACHE))
ANSIBLE_CACHE_CHECK=$(wildcard $(CACHE)/ansible.cache)
endif

$(BUILDDIR)/include/openenclave:
ifeq ($(CACHE_CHECK),)
	$(MAKE) submodule
	$(MAKE) openenclave
else
	$(MAKE) fetch_oecache
endif

fetch_oecache: $(TOP)/build/openenclave $(TOP)/build/bin/myst-gdb

$(TOP)/build/openenclave:
	mkdir -p $(BUILDDIR)
	rm -rf $(BUILDDIR)/openenclave
	cp -r $(CACHE) $(BUILDDIR)/openenclave

$(TOP)/build/bin/myst-gdb:
	mkdir -p $(BUILDDIR)/bin
	rm -f $(BUILDDIR)/bin/myst-gdb
	ln -s $(BUILDDIR)/openenclave/bin/oegdb $(BUILDDIR)/bin/myst-gdb

##==============================================================================
##
## submodule:
##
##==============================================================================

FETCH_SUBMODULE = git submodule update --init --progress

submodule:
	$(MAKE) .checkout_openenclave
	( cd openenclave; $(FETCH_SUBMODULE) tools/oeedger8r-cpp )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/mbedtls/mbedtls )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/openssl/openssl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/snmalloc )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/openssl/intel-sgx-ssl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/musl/musl )

.checkout_openenclave:
	git clone $(URL) -b $(BRANCH)
	touch .checkout_openenclave

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
ifeq ($(ANSIBLE_CACHE_CHECK),)
	$(MAKE) ansible
	mkdir -p $(CACHE)
	touch $(CACHE)/ansible.cache
endif
	mkdir -p $(OPENENCLAVE_BUILD)

ansible:
ifneq ($(MYST_IGNORE_ANSIBLE),1)
	$(MAKE) __ansible
endif

export ANSIBLE_SKIP_CONFLICT_CHECK=1

__ansible:
	sudo -H $(OPENENCLAVE_SRC)/scripts/ansible/install-ansible.sh || /bin/true
	sudo -H ansible-playbook $(OPENENCLAVE_SRC)/scripts/ansible/oe-contributors-acc-setup-no-driver.yml

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

$(OPENENCLAVE_BUILD)/Makefile:
	rm -rf $(OPENENCLAVE_BUILD)
	mkdir -p $(OPENENCLAVE_BUILD)
	touch $(DEPENDENCY_TARGET)
	( cd $(OPENENCLAVE_BUILD); cmake $(CMAKE_OPTS) $(OPENENCLAVE_SRC) )

install_oe:
	$(MAKE) -C $(OPENENCLAVE_BUILD) install
ifdef MYST_USE_BUILD_CACHE
	rm -rf $(CACHE)
	$(MAKE) -C $(OPENENCLAVE_BUILD) install DESTDIR=$(CACHE_DIR)/tmp
	mv $(CACHE_DIR)/tmp/$(OPENENCLAVE_INSTALL_PREFIX) $(CACHE)
	rm -rf $(CACHE_DIR)/tmp
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
DISTCLEAN += .checkout_openenclave openenclave

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
