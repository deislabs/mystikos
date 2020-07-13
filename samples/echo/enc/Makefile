TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM=echo_enc

SOURCES = echo_t.c crt.c enc.c

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS)

CLEAN = echo_t.h echo_t.c echo_args.h

include $(TOP)/rules.mak

echo_t.c:
	$(EDGER8R) --trusted --search-path $(INCDIR) ../echo.edl
