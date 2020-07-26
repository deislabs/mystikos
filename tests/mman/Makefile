SUBDIR = samples/mman
TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = enc

SOURCES = $(SUBOBJDIR)/run_t.c enc.c

INCLUDES = -I$(INCDIR) -I$(TOP)/include -I$(SUBOBJDIR) -I$(TOP)/enclave

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS) -L$(LIBDIR) -loel

CLEAN = $(SUBOBJDIR)/run_t.h $(SUBOBJDIR)/run_t.c $(SUBOBJDIR)/run_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/run_t.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../run/run.edl

tests:
	$(BINDIR)/run $(SUBBINDIR)/enc
