SUBDIR = tools/oelrun/host
TOP=$(abspath ../../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = oelrun

SOURCES = $(SUBOBJDIR)/oelrun_u.c $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = $(SUBOBJDIR)/oelrun_u.h $(SUBOBJDIR)/oelrun_u.c $(SUBOBJDIR)/oelrun_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/oelrun_u.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../oelrun.edl
