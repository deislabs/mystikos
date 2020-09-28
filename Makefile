.PHONY: tests
SUBDIR = top
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

##==============================================================================
##
## dirs:
##
##==============================================================================

DIRS += third_party
DIRS += gcov
DIRS += json
DIRS += glibccompat
DIRS += utils
DIRS += host
DIRS += target
DIRS += kernel
DIRS += crt
DIRS += oesdk
DIRS += tools
DIRS += alpine
DIRS += tests

CLEAN = $(BUILDDIR)

REDEFINE_TESTS=1
include $(TOP)/rules.mak

##==============================================================================
##
## distclean:
##
##==============================================================================

distclean: clean
	rm -rf $(TOP)/build
	$(MAKE) -C third_party/openenclave distclean
	$(MAKE) -C third_party/enclave-musl distclean
	$(MAKE) -C third_party/host-musl distclean

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

SOURCES_DIRS = $(shell  ls -d -1 */ | grep -v third_party | grep -v build | grep -v solutions)

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
