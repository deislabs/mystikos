SUBDIR = kernel
TOP=$(abspath ..)
include $(TOP)/defs.mak
include $(TOP)/config.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboskernel.a

SOURCES = $(wildcard *.c) $(wildcard ../shared/*.c) $(wildcard *.s)

INCLUDES = -I$(INCDIR) $(OEENCLAVE_INCLUDES) -I$(BUILDDIR)/include

ifdef LIBOS_ENABLE_HOST_THREADS
DEFINES = -DLIBOS_ENABLE_HOST_THREADS
endif

CFLAGS = $(OEENCLAVE_CFLAGS)

DIRS = image

include $(TOP)/rules.mak
