TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR = $(LIBDIR)

CC = $(MUSL_GCC)

ARCHIVE = libopenenclave.a

INCLUDES = -I$(OE_INCDIR) -I$(INCDIR)

CFLAGS = -fPIC

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

SOURCES = stubs.c

include $(TOP)/rules.mak
