TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = mman_err

SOURCES = $(wildcard *.c)

CFLAGS = $(DEFAULT_CFLAGS)

CLEAN = rootfs

include $(TOP)/rules.mak

tests:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs
	@ $(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROGRAM)
