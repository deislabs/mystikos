SUBDIR = enclave
TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboel.a

SOURCES = strings.c mutex.c spinlock.c mman.c

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEENCLAVE_CFLAGS)

include $(TOP)/rules.mak
