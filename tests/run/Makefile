TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBBINDIR=$(TOP)/build/bin

PROGRAM = run

SOURCES = $(SUBOBJDIR)/run_u.c host.c

INCLUDES = $(OEHOST_INCLUDES) -I$(SUBOBJDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = $(SUBOBJDIR)/run_u.h $(SUBOBJDIR)/run_u.c $(SUBOBJDIR)/run_args.h

include $(TOP)/rules.mak

$(SUBOBJDIR)/run_u.c:
	$(EDGER8R) $(EDGER8R_UNTRUSTED_OPTS) run.edl

run:
	$(SUBBINDIR)/host

tests:
