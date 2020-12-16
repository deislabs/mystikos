.PHONY: tests
SUBDIR = top
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

VERSION=$(shell cat VERSION)
PKGNAME=openlibos-$(VERSION)-x86_64
TARBALL=$(PKGNAME).tar.gz

##==============================================================================
##
## dirs:
##
##==============================================================================

DIRS += third_party

ifndef LIBOS_PRODUCT_BUILD
endif

ifdef LIBOS_ENABLE_GCOV
DIRS += gcov
endif

DIRS += json
DIRS += utils
DIRS += host
DIRS += target
DIRS += kernel
DIRS += crt
DIRS += oe
DIRS += tools

ifndef LIBOS_PRODUCT_BUILD
DIRS += alpine
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
	rm -rf $(TOP)/build

##==============================================================================
##
## size: print the executable size of various components
##
##==============================================================================

size:
	@ size -d $(BUILDDIR)/lib/openenclave/libosenc.so
	@ size -d $(BUILDDIR)/lib/liboskernel.so
	@ size -d $(BUILDDIR)/lib/liboscrt.so

##==============================================================================
##
## install:
## uninstall:
##
##==============================================================================

INSTALL=install -D
INSTDIR=$(DESTDIR)/$(LIBOS_PREFIX)

install:
	rm -rf $(INSTDIR)
	$(INSTALL) $(BINDIR)/libos $(INSTDIR)/bin/libos
	$(INSTALL) $(LIBDIR)/liboscrt.so $(INSTDIR)/lib/liboscrt.so
	$(INSTALL) $(LIBDIR)/liboskernel.so $(INSTDIR)/lib/liboskernel.so
	$(INSTALL) $(LIBDIR)/openenclave/libosenc.so $(INSTDIR)/lib/openenclave/libosenc.so
	$(INSTALL) $(BUILDDIR)/openenclave/bin/oegdb $(INSTDIR)/bin/libos-gdb
	$(INSTALL) ./scripts/appbuilder $(INSTDIR)/bin/libos-appbuilder
	$(INSTALL) include/libos/tee.h $(INSTDIR)/include/libos/tee.h
	$(INSTALL) $(BINDIR)/../musl/bin/musl-gcc $(INSTDIR)/bin/libos-gcc
	rm -rf $(INSTDIR)/lib/openenclave/debugger
	cp -r $(BUILDDIR)/openenclave/lib/openenclave/debugger $(INSTDIR)/lib/openenclave/debugger

uninstall:
	rm -rf $(LIBOS_PREFIX)

##==============================================================================
##
## src:
##     Print the list of libos sources (excluding third-party sources)
##
##==============================================================================

SOURCES_DIRS = $(shell  ls -d -1 */ | grep -v third_party | grep -v build )

src:
	@ echo $(foreach i, $(SOURCES_DIRS), $(shell find $(i) -name '*.[ch]'))

##==============================================================================
##
## format:
##     Format C source code within the source tree (exclude third_party)
##
##==============================================================================

format:
	./scripts/code-format $(shell $(MAKE) src)

##==============================================================================
##
## touch:
##     touch all the libos source files
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
	@ $(MAKE) -s -C tests tests RUNTEST=$(RUNTEST_COMMAND)
	@ $(MAKE) -s summary

alltests:
	$(MAKE) -s tests ALLTESTS=1 VERBOSE=1


##==============================================================================
##
## sub:
##     Apply /tmp/sub.sed to all libos sources
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
	@ ( cd $(BUILDDIR)/bindist/opt; tar zcf $(TARBALL) openlibos )
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
