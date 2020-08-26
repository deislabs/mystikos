SUBDIR = target/sgx
TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libostargetsgx.a

SOURCES = $(wildcard *.c)

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc
INCLUDES += -I$(INCDIR)/openenclave/3rdparty

CFLAGS = $(OEENCLAVE_CFLAGS)

include $(TOP)/rules.mak
