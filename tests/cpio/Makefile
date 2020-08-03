SUBDIR = samples/cpio
TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = enc host

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(SUBBINDIR)/host/host $(SUBBINDIR)/enc/enc cpio
