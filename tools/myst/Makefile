TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = enc host

include $(TOP)/rules.mak

run: main
	$(BINDIR)/myst rootfs /bin/main one two three
