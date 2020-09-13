TOP=$(abspath ../../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libostargetsgxenclave.a

SOURCES += $(wildcard *.c)
SOURCES += ../../shared/runthread.c

CFLAGS = $(OEENCLAVE_CFLAGS)

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(INCDIR)

include $(TOP)/rules.mak
