TOP=$(abspath ../..)
SUBDIR = tests/conf
SUBBINDIR=$(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(SUBBINDIR)/main conf
