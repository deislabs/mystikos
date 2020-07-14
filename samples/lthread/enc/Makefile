SUBDIR = samples/lthread/enc
TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = enc

SOURCES = $(SUBOBJDIR)/calls_t.c crt.c enc.c

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR)

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS) -L$(LIBDIR) -llthread

CLEAN = $(SUBOBJDIR)/calls_t.h $(SUBOBJDIR)/calls_t.c $(SUBOBJDIR)/calls_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/calls_t.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../calls.edl
