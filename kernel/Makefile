SUBDIR = kernel
TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboskernel.a

SOURCES = $(wildcard *.c) $(wildcard ../shared/*.c) $(wildcard *.s)

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = $(OEENCLAVE_CFLAGS)

POST_DIRS = image

include $(TOP)/rules.mak
