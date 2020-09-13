TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libostargetlinux.a

SOURCES += $(wildcard *.c)
SOURCES += ../shared/waitwake.c
SOURCES += ../shared/runthread.c

CFLAGS = $(DEFAULT_CFLAGS)

INCLUDES = -I$(INCDIR)

include $(TOP)/rules.mak
