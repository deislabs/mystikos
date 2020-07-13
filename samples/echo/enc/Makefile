TOP=$(abspath ../../..)
include $(TOP)/defs.mak

DIRECTORY = samples/echo/enc

PROGRAM = enc

SOURCES = calls_t.c crt.c enc.c

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS)

CLEAN = calls_t.h calls_t.c calls_args.h

include $(TOP)/rules.mak

calls_t.c:
	$(EDGER8R) --trusted --search-path $(INCDIR) ../calls.edl
