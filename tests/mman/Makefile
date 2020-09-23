TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = mman

SOURCES = $(wildcard *.c)
SOURCES += $(TOP)/kernel/mman.c
SOURCES += $(wildcard $(TOP)/shared/strings.c)
SOURCES += $(wildcard $(TOP)/compat/strings.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

CLEAN = rootfs

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/mman
