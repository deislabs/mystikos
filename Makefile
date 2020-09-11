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
## format:
##     Format C source code within the source tree (exclude third_party)
##
##==============================================================================

SOURCES_DIRS = $(filter-out third_party, $(DIRS)) include/libos

sources:
	@ echo $(foreach i, $(SOURCES_DIRS), $(shell find $(i) -name '*.[ch]'))

format:
	./scripts/code-format $(shell $(MAKE) sources)
