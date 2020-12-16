TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libostargetcommon.a

SOURCES += $(wildcard *.c)

CFLAGS = $(DEFAULT_CFLAGS)

ifdef LIBOS_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

INCLUDES = -I$(INCDIR)

include $(TOP)/rules.mak
