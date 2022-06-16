.NOTPARALLEL:

TOP=$(abspath $(CURDIR)/../..)

BUILDDIR=${TOP}/build

URL=https://github.com/openenclave/openenclave
BRANCH=master
COMMIT=d8e6c143eef73bce8306960c874b694e5317e02e

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
	$(MAKE) build
else
	$(MAKE) fetch_oecache
endif

build:
	$(MAKE) configure_oe
	$(MAKE) install_oe

fetch_oecache: $(TOP)/build/openenclave $(TOP)/build/lib/openenclave/debugger \
	$(TOP)/build/bin/myst-lldb

$(TOP)/build/openenclave:
	mkdir -p $(BUILDDIR)
	rm -rf $(BUILDDIR)/openenclave
	cp -r $(CACHE) $(BUILDDIR)/openenclave

$(TOP)/build/lib/openenclave/debugger: $(TOP)/build/openenclave
	mkdir -p $(BUILDDIR)/lib/openenclave
	rm -f $(BUILDDIR)/lib/openenclave/debugger
	ln -s $(BUILDDIR)/openenclave/lib/openenclave/debugger $(BUILDDIR)/lib/openenclave/debugger

$(TOP)/build/bin/myst-lldb: $(TOP)/build/openenclave
	mkdir -p $(BUILDDIR)/bin
	rm -f $(BUILDDIR)/bin/myst-lldb
	ln -s $(BUILDDIR)/openenclave/bin/oelldb $(BUILDDIR)/bin/myst-lldb

FETCH_SUBMODULE = git submodule update --init --progress

openenclave:
	git clone $(URL)
	( cd openenclave; git checkout $(COMMIT) )
	( cd openenclave; $(FETCH_SUBMODULE) tools/oeedger8r-cpp )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/musl/musl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/mbedtls/mbedtls )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/openssl/openssl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/openssl/intel-sgx-ssl )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/snmalloc )
	( cd openenclave; $(FETCH_SUBMODULE) 3rdparty/symcrypt_engine/SymCrypt-OpenSSL )
	$(MAKE) configure_oe

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
	cp ${OPENENCLAVE_BUILD}/output/lib/openenclave/host/liboesign.a ${TOP}/build/openenclave/lib/openenclave/host
ifdef MYST_USE_BUILD_CACHE
	rm -rf $(CACHE)
	$(MAKE) -C $(OPENENCLAVE_BUILD) install DESTDIR=$(CACHE_DIR)/tmp
	cp ${OPENENCLAVE_BUILD}/output/lib/openenclave/host/liboesign.a ${CACHE_DIR}/tmp/${OPENENCLAVE_INSTALL_PREFIX}/lib/openenclave/host
	mv $(CACHE_DIR)/tmp/$(OPENENCLAVE_INSTALL_PREFIX) $(CACHE)
	rm -rf $(CACHE_DIR)/tmp
endif
	mkdir -p $(TOP)/build/bin
	mkdir -p $(TOP)/build/lib/openenclave
	rm -f ${TOP}/build/lib/openenclave/debugger
	ln -s ${TOP}/build/openenclave/lib/openenclave/debugger ${TOP}/build/lib/openenclave/debugger
	# Patch minimum required lldb version from 7 to 8.
	sed -i 's/-7/-8/g' $(TOP)/build/openenclave/bin/oelldb
	rm -f $(TOP)/build/bin/myst-lldb
	ln -s $(TOP)/build/openenclave/bin/oelldb $(TOP)/build/bin/myst-lldb

clean:
	rm -rf $(TOP)/build/openenclave
	rm -f ${TOP}/build/lib/openenclave/debugger
	rm -f $(TOP)/build/bin/myst-lldb

distclean: clean
	rm -rf openenclave
