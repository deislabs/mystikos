TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetlinux.a

SOURCES += $(wildcard *.c)
SOURCES += ../shared/waitwake.c
SOURCES += ../shared/runthread.c
SOURCES += ../shared/poll.c

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

INCLUDES = -I$(INCDIR)

ifdef MYST_DEBUG_MALLOC
DEFINES += -DMYST_DEBUG_MALLOC
endif

include $(TOP)/rules.mak
