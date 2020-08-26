SUBDIR = target/sgx
TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libostargetsgx.a

SOURCES = $(wildcard *.c)

CFLAGS = $(OEENCLAVE_CFLAGS)

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(INCDIR)

include $(TOP)/rules.mak
