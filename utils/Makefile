TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libosutils.a

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/host-musl/include

CFLAGS =
CFLAGS += $(DEFAULT_CFLAGS)
CFLAGS += -Os
CFLAGS += -nostdinc
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses

LDFLAGS = $(DEFAULT_LDFLAGS)

include $(TOP)/rules.mak
