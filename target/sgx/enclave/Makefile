TOP=$(abspath ../../..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetsgxenclave.a

SOURCES += $(wildcard *.c)
SOURCES += ../../shared/runthread.c
SOURCES += ../../shared/luks.c
SOURCES += ../../shared/crypto.c
SOURCES += ../../shared/sha256.c
SOURCES += ../../shared/verify.c

CFLAGS = $(OEENCLAVE_CFLAGS)

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(INCDIR)

include $(TOP)/rules.mak
