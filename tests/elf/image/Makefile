TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = image

SOURCES = $(wildcard *.c)

INCLUDES = -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS)

LIBS = $(LIBDIR)/libmysthost.a

include $(TOP)/rules.mak
