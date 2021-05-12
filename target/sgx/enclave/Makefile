TOP=$(abspath ../../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetsgxenclave.a

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

SOURCES += $(wildcard *.c)
SOURCES += ../../shared/runthread.c
SOURCES += ../../shared/luks.c
SOURCES += ../../shared/crypto.c
SOURCES += ../../shared/sha256.c
SOURCES += ../../shared/verify.c
SOURCES += ../../shared/cpuinfo.c

CFLAGS = $(OEENCLAVE_CFLAGS)

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(INCDIR)

include $(TOP)/rules.mak
