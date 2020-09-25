TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboshost.a

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

include $(TOP)/rules.mak
