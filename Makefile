.PHONY: tests
SUBDIR = top
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

VERSION=$(shell cat VERSION)
PKGNAME=mystikos-$(VERSION)-x86_64
TARBALL=$(PKGNAME).tar.gz
DEBIAN_PACKAGE=$(PKGNAME).deb

all:
ifndef MYST_IGNORE_PREREQS
	$(MAKE) .git/hooks/pre-commit
endif
	$(MAKE) init
	$(MAKE) dirs

.git/hooks/pre-commit:
	cp scripts/pre-commit .git/hooks/pre-commit

##==============================================================================
##
## dirs:
##
##==============================================================================

# CAUTION: this must be run before all other targets
ifndef MYST_IGNORE_PREREQS
DIRS += prereqs
endif

DIRS += third_party

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
DIRS += debugger

ifdef MYST_WORLD
DIRS += alpine/docker
DIRS += tests
endif

CLEAN = $(BUILDDIR) $(TARBALL)

REDEFINE_TESTS=1
REDEFINE_CLEAN=1
include $(TOP)/rules.mak

##==============================================================================
##
## world: build the whole world (third-party + Mystikos + tests)
##
##==============================================================================

world:
	$(MAKE) MYST_WORLD=1

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	$(MAKE) __clean MYST_WORLD=1

##==============================================================================
##
## init:
##
##==============================================================================

build-prereqs:
	make -C $(TOP)/prereqs/

init: build-prereqs
	make init -C $(TOP)/third_party/

##==============================================================================
##
## build:
##
##==============================================================================

build:
	make dirs MYST_IGNORE_PREREQS=1

##==============================================================================
##
## release-build:
##
##==============================================================================

release-build:
	make build
	make bindist

##==============================================================================
##
## distclean:
##
##==============================================================================

distclean: clean
	sudo rm -rf $(TOP)/build
	make distclean -C $(TOP)/third_party/

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
	$(INSTALL) $(BINDIR)/myst-gdb $(INSTDIR)/bin/myst-gdb
	$(INSTALL) $(LIBDIR)/debugger/gdb-sgx-plugin/mprotect.py $(INSTDIR)/lib/debugger/gdb-sgx-plugin/mprotect.py
	$(INSTALL) $(LIBDIR)/debugger/gdb-sgx-plugin/symbol_analyzer.py $(INSTDIR)/lib/debugger/gdb-sgx-plugin/symbol_analyzer.py
	$(INSTALL) $(LIBDIR)/debugger/gdb-sgx-plugin/print.py $(INSTDIR)/lib/debugger/gdb-sgx-plugin/print.py
	$(INSTALL) ./scripts/myst-retry $(INSTDIR)/bin/myst-retry
	$(INSTALL) ./scripts/appbuilder $(INSTDIR)/bin/myst-appbuilder
	$(INSTALL) include/myst/tee.h $(INSTDIR)/include/myst/tee.h
	$(INSTALL) include/myst/ssr.h $(INSTDIR)/include/myst/ssr.h
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
## solutions:
##
##==============================================================================

solutions_tests:
	$(MAKE) -C solutions tests RUNTEST=$(RUNTEST_COMMAND)
	@ TESTDIR=$(BUILDDIR)/solutions $(MAKE) -s summary

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
	@ rm -rf $(BUILDDIR)/bindist $(PKGNAME)
	@ $(MAKE) install DESTDIR=$(BUILDDIR)/bindist
	@ ( cd $(BUILDDIR)/bindist/opt; tar zcf $(TARBALL) mystikos )
	@ mv $(BUILDDIR)/bindist/opt/$(TARBALL) .
	@ echo "Created tarball: $(TARBALL)"
	@ mkdir -p $(PKGNAME)/DEBIAN
	@ ( cp -r $(BUILDDIR)/bindist/opt $(PKGNAME); cp package/control $(PKGNAME)/DEBIAN )
	@ echo "Version: $(VERSION)" >> $(PKGNAME)/DEBIAN/control
	@ dpkg-deb --build --root-owner-group $(PKGNAME)
	@ echo "Created Debian package: $(DEBIAN_PACKAGE)"
	@ rm -rf $(PKGNAME)

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
	@ echo "make -- build Mystikos except for tests"
	@ echo "make init -- initialize all dependencies"
	@ echo "make world -- build the whole world (third-party + Mystikos + tests)"
	@ echo "make build -- build everything except for prereqs and tests"
	@ echo "make release-build -- runs 'build' followed by 'bindist'"
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
