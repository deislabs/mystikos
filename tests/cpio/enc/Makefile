SUBDIR = tests/cpio/enc
TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = enc

SOURCES = $(SUBOBJDIR)/calls_t.c enc.c

INCLUDES = -I$(SUBOBJDIR) $(OEENCLAVE_INCLUDES)

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS) -L$(LIBDIR) -llthread

LIBS =
LIBS += $(LIBDIR)/liboskernel.a
LIBS += $(LIBDIR)/libostargetsgx.a

CLEAN = $(SUBOBJDIR)/calls_t.h $(SUBOBJDIR)/calls_t.c $(SUBOBJDIR)/calls_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/calls_t.c:
	$(EDGER8R) $(EDGER8R_OPTS) ../calls.edl
