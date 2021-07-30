TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetcommon.a

SOURCES += $(wildcard *.c)

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_RELEASE
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

INCLUDES = -I$(INCDIR)

include $(TOP)/rules.mak
