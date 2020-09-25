TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libosutils.a

SOURCES = $(wildcard *.c)

INCLUDES = $(DEFAULT_INCLUDES)

CFLAGS = $(DEFAULT_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(DEFAULT_LDFLAGS) $(GCOV_LDFLAGS)

include $(TOP)/rules.mak
