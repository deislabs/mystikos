.PHONY: tests
SUBDIR = top
TOP = $(abspath $(CURDIR))
include $(TOP)/defs.mak

DIRS = third_party host target kernel tools alpine tests

include $(TOP)/rules.mak

distclean: clean
	rm -rf $(TOP)/build
	$(MAKE) -C third_party/openenclave distclean

size:
	@ size -d $(BUILDDIR)/bin/enc/libosenc.so
	@ size -d $(BUILDDIR)/bin/liboskernel.so
	@ size -d $(BUILDDIR)/bin/enc/liboscrt.so
