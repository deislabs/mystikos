TOP=$(abspath ../..)
SUBDIR = tests/elf
SUBBINDIR=$(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR) -I$(TOP)/include

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a

include $(TOP)/rules.mak

tests:
	$(SUBBINDIR)/main

vg:
	valgrind --tool=memcheck --leak-check=full $(SUBBINDIR)/main
