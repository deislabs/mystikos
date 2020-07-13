TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = host

SOURCES = calls_u.c host.c

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = calls_u.h calls_u.c calls_args.h

include $(TOP)/rules.mak

calls_u.c:
	$(EDGER8R) --untrusted --search-path $(INCDIR) ../calls.edl
