TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = round

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a
LIBS = $(LIBDIR)/libosutils.a

REDEFINE_TESTS=1

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/round
