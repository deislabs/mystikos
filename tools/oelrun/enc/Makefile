SUBDIR = tools/oelrun/enc
TOP=$(abspath ../../..)
SUBBINDIR=$(TOP)/build/bin/enc
include $(TOP)/defs.mak

PROGRAM = liboelenc.so

SOURCES = $(SUBOBJDIR)/oelrun_t.c enc.c

INCLUDES += -I$(INCDIR)
INCLUDES += -I$(TOP)/include
INCLUDES += -I$(SUBOBJDIR)
INCLUDES += -I$(INCDIR)/openenclave/3rdparty/libc

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = -L$(LIBDIR) -loehostfs -loel -llthread $(OEENCLAVE_LDFLAGS)

CLEAN = $(SUBOBJDIR)/oelrun_t.h $(SUBOBJDIR)/oelrun_t.c $(SUBOBJDIR)/oelrun_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/oelrun_t.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../oelrun.edl

vars:
	@echo "SUBDIR=$(SUBDIR)"
	@echo "SUBLIBDIR=$(SUBLIBDIR)"
	@echo "SUBBINDIR=$(SUBBINDIR)"
	@echo "SUBOBJDIR=$(SUBOBJDIR)"
	@echo "OBJDIR=$(OBJDIR)"
