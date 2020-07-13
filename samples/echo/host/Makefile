TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = echo_host

SOURCES = echo_u.c host.c

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = echo_u.h echo_u.c echo_args.h

include $(TOP)/rules.mak

echo_u.c:
	$(EDGER8R) --untrusted --search-path $(INCDIR) ../echo.edl
