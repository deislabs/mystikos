SUBDIR = tools/oelrun
TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = enc host

include $(TOP)/rules.mak

run: main
	$(BINDIR)/oelrun rootfs /bin/main one two three
