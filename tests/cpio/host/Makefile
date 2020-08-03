SUBDIR = samples/cpio/host
TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = host

SOURCES = $(SUBOBJDIR)/calls_u.c host.c

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = $(SUBOBJDIR)/calls_u.h $(SUBOBJDIR)/calls_u.c $(SUBOBJDIR)/calls_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/calls_u.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../calls.edl
