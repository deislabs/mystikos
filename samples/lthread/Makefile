SUBDIR = samples/lthread
TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = enc host

include $(TOP)/rules.mak

tests:
	$(SUBBINDIR)/host/host $(SUBBINDIR)/enc/enc

gdb:
	$(BINDIR)/oegdb $(SUBBINDIR)/host/host --args $(SUBBINDIR)/enc/enc
