SUBDIR = enclave
TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboskernel.a

SOURCES = $(wildcard *.c) $(wildcard ../shared/*.c)

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = $(OEENCLAVE_CFLAGS)

DEPENDS += $(TOP)/include/libos/fs.h
DEPENDS += $(TOP)/include/libos/ramfs.h

include $(TOP)/rules.mak
