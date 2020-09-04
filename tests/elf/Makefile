TOP=$(abspath ../..)
SUBDIR = tests/elf
include $(TOP)/defs.mak

DIRS = image

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

IMAGE = $(TOP)/build/bin/tests/elf/image/image

tests:
	$(SUBBINDIR)/main $(IMAGE)
