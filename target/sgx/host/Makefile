TOP=$(abspath ../../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetsgxhost.a

SOURCES += ../../shared/waitwake.c
SOURCES += ../../shared/poll.c

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_RELEASE
CFLAGS += -O3
endif

INCLUDES = -I$(INCDIR)

include $(TOP)/rules.mak
