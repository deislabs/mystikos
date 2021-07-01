.PHONY: tests
SUBDIR = top
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

VERSION=$(shell cat VERSION)
PKGNAME=mystikos-$(VERSION)-x86_64
TARBALL=$(PKGNAME).tar.gz

all:
	$(MAKE) .git/hooks/pre-commit
	$(MAKE) dirs

.git/hooks/pre-commit:
	cp scripts/pre-commit .git/hooks/pre-commit

##==============================================================================
##
## dirs:
##
##==============================================================================

# CAUTION: this must be run before all other targets
DIRS += prereqs

DIRS += third_party

ifndef MYST_PRODUCT_BUILD
endif

ifdef MYST_ENABLE_GCOV
DIRS += gcov
endif

DIRS += json
DIRS += utils

ifdef MYST_ENABLE_EXT2FS
DIRS += ext2
endif

ifdef MYST_ENABLE_HOSTFS
DIRS += hostfs
endif

DIRS += host
DIRS += target
DIRS += kernel
DIRS += crt
DIRS += oe
DIRS += tools

ifndef MYST_PRODUCT_BUILD
DIRS += alpine/docker
DIRS += tests
endif

CLEAN = $(BUILDDIR) $(TARBALL)

REDEFINE_TESTS=1
include $(TOP)/rules.mak

##==============================================================================
##
## distclean:
##
##==============================================================================

distclean: clean
	rm -rf $(TOP)/third_party/musl/crt/musl
	make distclean -C $(TOP)/third_party/openenclave
	sudo rm -rf $(TOP)/build

##==============================================================================
##
## size: print the executable size of various components
##
##==============================================================================

size:
	@ size -d $(BUILDDIR)/lib/openenclave/mystenc.so
	@ size -d $(BUILDDIR)/lib/libmystkernel.so
	@ size -d $(BUILDDIR)/lib/libmystcrt.so

##==============================================================================
##
## install:
## uninstall:
##
##==============================================================================

INSTALL=install -D
INSTDIR=$(DESTDIR)/$(MYST_PREFIX)

install:
	rm -rf $(INSTDIR)
	$(INSTALL) $(BINDIR)/myst $(INSTDIR)/bin/myst
	$(INSTALL) $(LIBDIR)/libmystcrt.so $(INSTDIR)/lib/libmystcrt.so
	$(INSTALL) $(LIBDIR)/libmystkernel.so $(INSTDIR)/lib/libmystkernel.so
	$(INSTALL) $(LIBDIR)/openenclave/mystenc.so $(INSTDIR)/lib/openenclave/mystenc.so
	$(INSTALL) $(BUILDDIR)/openenclave/bin/oegdb $(INSTDIR)/bin/myst-gdb
	$(INSTALL) ./scripts/appbuilder $(INSTDIR)/bin/myst-appbuilder
	$(INSTALL) include/myst/tee.h $(INSTDIR)/include/myst/tee.h
	$(INSTALL) $(BINDIR)/../musl/bin/musl-gcc $(INSTDIR)/bin/myst-gcc
	rm -rf $(INSTDIR)/lib/openenclave/debugger
	cp -r $(BUILDDIR)/openenclave/lib/openenclave/debugger $(INSTDIR)/lib/openenclave/debugger

uninstall:
	rm -rf $(MYST_PREFIX)

##==============================================================================
##
## src:
##     Print the list of myst sources (excluding third-party sources)
##
##==============================================================================

src:
	@ ./scripts/sources

##==============================================================================
##
## format:
##     Format C source code within the source tree (exclude third_party)
##
##==============================================================================

format:
	./scripts/code-format $(shell ./scripts/sources)

format-staged:
	./scripts/code-format $(shell ./scripts/sources --staged)

##==============================================================================
##
## touch:
##     touch all the myst source files
##
##==============================================================================

touch:
	touch $(shell $(MAKE) src)

##==============================================================================
##
## attn:
##     Find "ATTN" strings in source code
##
##==============================================================================

attn:
	@ grep "ATTN" $(shell $(MAKE) src) | more

##==============================================================================
##
## tests:
##
##==============================================================================

summary:
	@ SUMMARY=1 $(RUNTEST_COMMAND) /bin/true

tests:
	@ $(MAKE) -C tests tests RUNTEST=$(RUNTEST_COMMAND)
	@ $(MAKE) -s summary

alltests:
	$(MAKE) tests ALLTESTS=1


##==============================================================================
##
## sub:
##     Apply /tmp/sub.sed to all myst sources
##
##==============================================================================

sub:
	@ $(TOP)/scripts/sub $(shell $(MAKE) src)

##==============================================================================
##
## bindist:
##     Create a binary distribution based on the VERSION file
##
##==============================================================================

bindist:
	@ rm -rf $(BUILDDIR)/bindist
	@ $(MAKE) install DESTDIR=$(BUILDDIR)/bindist
	@ ( cd $(BUILDDIR)/bindist/opt; tar zcf $(TARBALL) mystikos )
	@ cp $(BUILDDIR)/bindist/opt/$(TARBALL) .
	@ echo "=== Created $(TARBALL)"

##==============================================================================
##
## nolicense:
##     Print names of source files without a license notice
##
##==============================================================================

nolicense:
	@ $(foreach i, $(shell $(MAKE) src), ( grep -q -l "// Copyright (c)" $(i) || echo $(i) ) $(NL) )

##==============================================================================
##
## oelicense:
##     Print names of source files with the OE license
##
##==============================================================================

oelicense:
	@ $(foreach i, $(shell $(MAKE) src), ( grep -l "// Copyright (c) Open Enclave" $(i) || /bin/true ) $(NL) )

##==============================================================================
##
## help:
##
##==============================================================================

help:
	@ echo ""
	@ echo "make -- build everything"
	@ echo "make clean -- remove generated binaries"
	@ echo "make distclean -- remove build configuration and binaries"
	@ echo "make tests -- run critical tests"
	@ echo "make alltests -- run all tests"
	@ echo "make install -- install the project"
	@ echo "make uninstall -- uninstall the project"
	@ echo "make touch -- touch all source files"
	@ echo "make bindist -- generate a binary distribution file"
	@ echo "make src -- print project source file names"
	@ echo "make nolicense -- print source file names no license"
	@ echo "make oelicense -- print source file names with OE SDK license"
	@ echo "make sub -- perform global substitution using /tmp/sub.sed"
	@ echo "make attn -- print sources with 'ATTN' annotations"
	@ echo "make format -- format all sources"
	@ echo ""
