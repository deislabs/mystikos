TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = enc

SOURCES = $(SUBOBJDIR)/calls_t.c enc.c

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEENCLAVE_CFLAGS)

LDFLAGS = $(OEENCLAVE_LDFLAGS) -L$(LIBDIR) -llthread

LIBS = $(LIBDIR)/liboskernel.a $(LIBDIR)/libostargetsgxenclave.a

ifdef LIBOS_ENABLE_GCOV
LIBS += $(LIBDIR)/libgcov_musl.a
endif

CLEAN = $(SUBOBJDIR)/calls_t.h $(SUBOBJDIR)/calls_t.c $(SUBOBJDIR)/calls_args.h

include $(TOP)/rules.mak

$(SUBOBJDIR)/calls_t.c:
	$(EDGER8R) $(EDGER8R_TRUSTED_OPTS) ../calls.edl
