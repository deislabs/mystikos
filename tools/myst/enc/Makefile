TOP=$(abspath ../../..)
SUBBINDIR=$(TOP)/build/lib/openenclave
include $(TOP)/defs.mak

PROGRAM = mystenc.so

SOURCES += $(SUBOBJDIR)/myst_t.c
SOURCES += enc.c
SOURCES += clock.c
SOURCES += syscall.c
SOURCES += ../config.c
SOURCES += enter.s

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(SUBOBJDIR) -I../

CFLAGS = $(OEENCLAVE_CFLAGS)

LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libmysttargetsgxenclave.a
LIBS += $(LIBDIR)/libmystutils.a

LDFLAGS += $(OEENCLAVE_LDFLAGS)
ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
LDFLAGS += $(GCOV_LDFLAGS)
LIBS += $(LIBDIR)/libgcov_musl.a
endif

CLEAN = $(SUBOBJDIR)/myst_t.h $(SUBOBJDIR)/myst_t.c $(SUBOBJDIR)/myst_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/myst_t.c: ../myst.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../myst.edl
