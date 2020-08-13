TOP=$(abspath ../..)
SUBDIR = tests/elf
SUBBINDIR=$(TOP)/build/bin
include $(TOP)/defs.mak

DIRS = image

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR) -I$(TOP)/include

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

IMAGE = $(TOP)/build/bin/tests/elf/image/image

tests:
	$(SUBBINDIR)/main $(IMAGE)

vg:
	valgrind --tool=memcheck --leak-check=full $(SUBBINDIR)/main $(IMAGE)
