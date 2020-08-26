TOP=$(abspath ../..)
SUBDIR = tests/run
SUBBINDIR=$(TOP)/build/bin
include $(TOP)/defs.mak

PROGRAM = run

SOURCES = $(SUBOBJDIR)/run_u.c host.c

INCLUDES = -I$(INCDIR) -I$(SUBOBJDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)

CLEAN = $(SUBOBJDIR)/run_u.h $(SUBOBJDIR)/run_u.c $(SUBOBJDIR)/run_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/run_u.c:
	$(EDGER8R) $(EDGER8R_OPTS) run.edl

run:
	$(SUBBINDIR)/host

tests:
