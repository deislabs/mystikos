.PHONY: tests
SUBDIR = top
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

##==============================================================================
##
## dirs:
##
##==============================================================================

DIRS = third_party gcov json host target kernel crt oesdk tools alpine tests

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

INSTALL = install -D

install: dirs uninstall
	$(INSTALL) $(BINDIR)/libos $(LIBOS_PREFIX)/bin/libos
	$(INSTALL) $(LIBDIR)/liboscrt.so $(LIBOS_PREFIX)/lib/liboscrt.so
	$(INSTALL) $(LIBDIR)/liboskernel.so $(LIBOS_PREFIX)/lib/liboskernel.so
	$(INSTALL) $(LIBDIR)/openenclave/libosenc.so $(LIBOS_PREFIX)/lib/openenclave/libosenc.so
	$(INSTALL) $(BUILDDIR)/openenclave/bin/oegdb $(LIBOS_PREFIX)/bin/libos-gdb
	rm -rf $(LIBOS_PREFIX)/lib/openenclave/debugger
	cp -r $(BUILDDIR)/openenclave/lib/openenclave/debugger $(LIBOS_PREFIX)/lib/openenclave/debugger

uninstall:
	rm -rf $(LIBOS_PREFIX)

##==============================================================================
##
## sources:
##     Print the list of libos sources (excluding third-party sources)
##
##==============================================================================

SOURCES_DIRS = $(filter-out third_party, $(DIRS)) include/libos

sources:
	@ echo $(foreach i, $(SOURCES_DIRS), $(shell find $(i) -name '*.[ch]'))

##==============================================================================
##
## format:
##     Format C source code within the source tree (exclude third_party)
##
##==============================================================================

format:
	./scripts/code-format $(shell $(MAKE) sources)

##==============================================================================
##
## touch:
##     touch all the libos source files
##
##==============================================================================

touch:
	touch $(shell $(MAKE) sources)

##==============================================================================
##
## attn:
##     Find "ATTN" strings in source code
##
##==============================================================================

attn:
	@ grep "ATTN" $(shell $(MAKE) sources) | more

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

pipeline-tests:
	$(MAKE) -s tests ALLTESTS=1 VERBOSE=1


##==============================================================================
##
## sub:
##     Apply /tmp/sub.sed to all libos sources
##
##==============================================================================

sub:
	@ $(TOP)/scripts/sub $(shell $(MAKE) sources)
