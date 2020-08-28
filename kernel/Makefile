SUBDIR = kernel
TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboskernel.a

SOURCES = $(wildcard *.c) $(wildcard ../shared/*.c) $(wildcard *.s)

INCLUDES = -I$(INCDIR) $(OEENCLAVE_INCLUDES) -I$(BUILDDIR)/include

#DEFINES = -DENABLE_HTHREADS=1

CFLAGS = $(OEENCLAVE_CFLAGS)

DIRS = image

include $(TOP)/rules.mak
