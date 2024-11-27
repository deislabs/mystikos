TOP = $(abspath $(CURDIR)/../..)
include $(TOP)/defs.mak

INSTALL_PREFIX=$(BUILDDIR)/mbedtls

URL=https://github.com/ARMmbed/mbedtls

BRANCH=v2.28.9

# get the hash of the remote github repository (for the given branch)
HASH=$(shell git ls-remote $(URL) -b $(BRANCH) | cut -f1 )

CACHE_DIR=$(HOME)/.mystikos/cache/mbedtls

ifdef MYST_USE_BUILD_CACHE
CACHE_CHECK=$(wildcard $(CACHE_DIR)/$(HASH))
endif

all:
ifeq ($(CACHE_CHECK),)
	$(MAKE) mbedtls
	$(MAKE) build
else
	$(MAKE) fetch_cache
endif

build:
	rm -rf $(INSTALL_PREFIX)
	$(MAKE) -C mbedtls install DESTDIR=$(INSTALL_PREFIX)
	$(MAKE) cache

fetch_cache:
	rm -rf $(INSTALL_PREFIX)
	cp -r $(CACHE_DIR)/$(HASH) $(INSTALL_PREFIX)

cache:
ifdef MYST_USE_BUILD_CACHE
	rm -rf $(CACHE_DIR)/$(HASH)
	mkdir -p $(CACHE_DIR)
	cp -r $(INSTALL_PREFIX) $(CACHE_DIR)/$(HASH)
endif

clean:
	( /usr/bin/test ! -d mbedtls || $(MAKE) -C mbedtls clean )

distclean:
	rm -rf mbedtls

mbedtls:
	git clone $(URL) -b $(BRANCH)

hash:
	echo $(HASH)
