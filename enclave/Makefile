SUBDIR = enclave
TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboel.a

SOURCES = $(wildcard *.c)

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = $(OEENCLAVE_CFLAGS)

DEPENDS += $(TOP)/include/oel/fs.h
DEPENDS += $(TOP)/include/oel/ramfs.h

include $(TOP)/rules.mak
