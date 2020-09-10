TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR = $(LIBDIR)

CC = $(MUSL_GCC)

ARCHIVE = liboesdkenclave.a

INCLUDES = -I$(OE_INCDIR) -I$(INCDIR)

CFLAGS = -fPIC

SOURCES = enclave.c

include $(TOP)/rules.mak
