TOP=$(abspath ../../..)
include $(TOP)/defs.mak
include $(TOP)/config.mak

URL=git://git.musl-libc.org/musl

BRANCH=v1.2.0

# get the hash of the remote github repository (for the given branch)
HASH1=$(shell git ls-remote $(URL) -b $(BRANCH) | cut -f1 )

# get the hash of the patch.diff file
HASH2=$(shell sha256sum patch.diff | cut -d' ' -f 1)

# get the composite hash (github repository and patch.diff file)
HASH=$(shell echo "$(HASH1)$(HASH2)" | sha256sum - | cut -d' ' -f 1)

CACHE_DIR=$(HOME)/.mystikos/cache/musl/crt

ifdef MYST_USE_BUILD_CACHE
CACHE_CHECK=$(wildcard $(CACHE_DIR)/$(HASH))
endif

WHICH_GCC = $(shell which gcc)

CFLAGS = -g -Werror -fPIC

ifeq ($(MYST_RELEASE),1)
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

THISDIR=$(CURDIR)

all:
ifeq ($(CACHE_CHECK),)
	$(MAKE) build
else
	$(MAKE) fetch_cache
endif

fetch_cache:
	rm -rf musl
	cp -r $(CACHE_DIR)/$(HASH) musl

build:
	$(MAKE) musl
	$(MAKE) musl/config.mak
	( cd musl; $(MAKE) CC="$(WHICH_GCC) $(CFLAGS)" )
	$(MAKE) cache

cache:
ifdef MYST_USE_BUILD_CACHE
	rm -rf $(CACHE_DIR)/$(HASH)
	mkdir -p $(CACHE_DIR)
	cp -r musl $(CACHE_DIR)/$(HASH)
endif

clean:
ifneq ($(wildcard musl),)
	( cd musl && make clean )
#	rm -f musl/config.mak
endif

distclean:
#ifneq ($(wildcard musl),)
#	rm -rf musl
#endif

musl/config.mak:
	( cd musl; ./configure --enable-debug=yes --disable-optimize )

tests:

genpatch: musl
	rm -f patch.diff
	( cd musl; git diff > $(THISDIR)/patch.diff )
	( cd musl; git diff --cached >> $(THISDIR)/patch.diff )

PATCHDIR=$(TOP)/third_party/musl/crt

NEWFILES =
NEWFILES += src/internal/__popcountdi2.c
NEWFILES += src/stdio/__fprintf_chk.c
NEWFILES += src/stdio/__vfprintf_chk.c
NEWFILES += src/unistd/preadv2.c
NEWFILES += src/unistd/pwritev2.c
NEWFILES += src/stdio/register_printf.c

musl:
#	mkdir -p $(BUILDDIR)
#	git clone $(URL) -b $(BRANCH) musl
#	( cd musl; git apply $(PATCHDIR)/patch.diff )
#	$(foreach i, $(NEWFILES), ( cd musl; git add $(i) ); $(NL) )
