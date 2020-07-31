SUBDIR = tools/libos/host
TOP=$(abspath ../../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = libos

SOURCES = $(SUBOBJDIR)/libos_u.c $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = $(SUBOBJDIR)/libos_u.h $(SUBOBJDIR)/libos_u.c $(SUBOBJDIR)/libos_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/libos_u.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../libos.edl
