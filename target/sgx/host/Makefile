TOP=$(abspath ../../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetsgxhost.a

SOURCES += ../../shared/waitwake.c
SOURCES += ../../shared/nanosleep.c
SOURCES += ../../shared/poll.c
SOURCES += ../../shared/epoll.c
SOURCES += ../../shared/interrupt.c

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_RELEASE
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

INCLUDES = -I$(INCDIR)

include $(TOP)/rules.mak
