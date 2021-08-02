TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetlinux.a

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

SOURCES += $(wildcard *.c)
SOURCES += ../shared/waitwake.c
SOURCES += ../shared/runthread.c
SOURCES += ../shared/poll.c
SOURCES += ../shared/luks.c
SOURCES += ../shared/sha256.c
SOURCES += ../shared/verify.c

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_RELEASE
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

INCLUDES = -I$(INCDIR) -I$(MBEDTLS_INCDIR) -I$(OE_INCDIR)

include $(TOP)/rules.mak
