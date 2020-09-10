TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libjson.a

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) -fPIC

LDFLAGS = $(OEHOST_LDFLAGS)

include $(TOP)/rules.mak
