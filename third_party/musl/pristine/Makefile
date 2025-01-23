TOP=$(abspath ../../.. )
include $(TOP)/defs.mak

URL=git://git.musl-libc.org/musl

BRANCH=v1.2.0

# get the hash of the remote github repository (for the given branch)
HASH=$(shell git ls-remote $(URL) -b $(BRANCH) | cut -f1 )

CACHE_DIR=$(HOME)/.mystikos/cache/musl/pristine

ifdef MYST_USE_BUILD_CACHE
CACHE_CHECK=$(wildcard $(CACHE_DIR)/$(HASH))
endif

PREFIX=$(BUILDDIR)/musl

all:
ifeq ($(CACHE_CHECK),)
	$(MAKE) musl
	$(MAKE) build
else
	$(MAKE) fetch_cache
endif

build:
	$(MAKE) musl/config.mak
	( cd musl; make install )
	$(MAKE) cache

fetch_cache:
	rm -rf $(PREFIX)
	mkdir -p $(BUILDDIR)
	cp -r $(CACHE_DIR)/$(HASH) $(PREFIX)

cache:
ifdef MYST_USE_BUILD_CACHE
	rm -rf $(CACHE_DIR)/$(HASH)
	mkdir -p $(CACHE_DIR)
	cp -r $(PREFIX) $(CACHE_DIR)/$(HASH)
endif

clean:
#	rm -rf musl

distclean: clean

musl/config.mak:
	( cd musl; ./configure --prefix=$(PREFIX) )

musl:
#	git clone $(URL) -b $(BRANCH)

tests:
