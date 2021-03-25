TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = maps

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS = $(LIBDIR)/libmystutils.a $(LIBDIR)/libmysthost.a

REDEFINE_TESTS=1

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/maps
