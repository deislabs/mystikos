TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libostargetlinux.a

SOURCES += $(wildcard *.c)
SOURCES += ../shared/waitwake.c
SOURCES += ../shared/runthread.c

CFLAGS = $(DEFAULT_CFLAGS)

INCLUDES = -I$(INCDIR)

ifdef LIBOS_DEBUG_MALLOC
DEFINES += -DLIBOS_DEBUG_MALLOC
endif

include $(TOP)/rules.mak
