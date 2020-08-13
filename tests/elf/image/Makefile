TOP=$(abspath ../../..)
SUBDIR = tests/elf/image
include $(TOP)/defs.mak

PROGRAM = image

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR) -I$(TOP)/include

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a

include $(TOP)/rules.mak
