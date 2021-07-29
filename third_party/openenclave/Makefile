.NOTPARALLEL:

TOP=$(abspath $(CURDIR)/../..)

BUILDDIR=${TOP}/build

URL=https://github.com/openenclave/openenclave
BRANCH=mystikos.v5

OPENENCLAVE_INSTALL_PREFIX=$(BUILDDIR)/openenclave
OPENENCLAVE_SRC = $(CURDIR)/openenclave
OPENENCLAVE_BUILD = $(CURDIR)/openenclave/build

# get the hash of the remote github repository (for the given branch)
HASH=$(shell git ls-remote $(URL) -b $(BRANCH) | cut -f1 )

CACHE_DIR=$(HOME)/.mystikos/cache/openenclave

CACHE=$(CACHE_DIR)/$(HASH)

all: $(BUILDDIR)/include/openenclave

ifdef MYST_USE_BUILD_CACHE
CACHE_CHECK=$(wildcard $(CACHE))
endif

$(BUILDDIR)/include/openenclave:
ifeq ($(CACHE_CHECK),)
	$(MAKE) openenclave
	$(MAKE) configure_oe
	$(MAKE) install_oe
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

FETCH_SUBMODULE = git submodule update --init --progress

openenclave:
	git clone $(URL) -b $(BRANCH)
	( cd openenclave; $(FETCH_SUBMODULE) tools/oeedger8r-cpp )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/musl/musl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/mbedtls/mbedtls )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/openssl/openssl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/openssl/intel-sgx-ssl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/snmalloc )

configure_oe: $(OPENENCLAVE_BUILD)/Makefile

CMAKE_OPTS =

ifeq ($(MYST_RELEASE),1)
CMAKE_OPTS += -DCMAKE_BUILD_TYPE=Release
else
CMAKE_OPTS += -DUSE_DEBUG_MALLOC=1
endif

CMAKE_OPTS += -DHAS_QUOTE_PROVIDER=OFF
CMAKE_OPTS += -DBUILD_TESTS=OFF
CMAKE_OPTS += -DENABLE_REFMAN=OFF
CMAKE_OPTS += -DCMAKE_INSTALL_PREFIX=$(OPENENCLAVE_INSTALL_PREFIX)

$(OPENENCLAVE_BUILD)/Makefile:
	rm -rf $(OPENENCLAVE_BUILD)
	mkdir -p $(OPENENCLAVE_BUILD)
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

clean:
	rm -rf $(TOP)/build/openenclave
	rm -f $(TOP)/build/bin/myst-gdb

distclean: clean
	rm -rf openenclave
