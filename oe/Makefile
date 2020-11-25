TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR = $(LIBDIR)

CC = $(MUSL_GCC)

ARCHIVE = libopenenclave.a

INCLUDES = -I$(OE_INCDIR) -I$(INCDIR)

CFLAGS = -fPIC

SOURCES = stubs.c

include $(TOP)/rules.mak
