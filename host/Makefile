TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = liboshost.a

SOURCES = $(wildcard *.c)
SOURCES += $(wildcard $(TOP)/shared/*.c)
SOURCES += $(wildcard $(TOP)/compat/*.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

include $(TOP)/rules.mak
