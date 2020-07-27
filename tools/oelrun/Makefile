SUBDIR = tools/oelrun
TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = enc host

include $(TOP)/rules.mak

run:
	$(BINDIR)/oelrun rootfs /bin/program one two three
