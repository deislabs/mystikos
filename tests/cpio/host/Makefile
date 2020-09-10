TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = host

SOURCES = $(SUBOBJDIR)/calls_u.c host.c

INCLUDES = $(OEHOST_INCLUDES) -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = $(SUBOBJDIR)/calls_u.h $(SUBOBJDIR)/calls_u.c $(SUBOBJDIR)/calls_args.h

LIBS += $(LIBDIR)/liboshost.a

include $(TOP)/rules.mak

$(SUBOBJDIR)/calls_u.c:
	$(EDGER8R) $(EDGER8R_UNTRUSTED_OPTS) ../calls.edl
