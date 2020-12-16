TOP=$(abspath ../../..)
SUBBINDIR=$(TOP)/build/lib/openenclave
include $(TOP)/defs.mak

PROGRAM = libosenc.so

SOURCES += $(SUBOBJDIR)/libos_t.c
SOURCES += enc.c
SOURCES += clock.c
SOURCES += syscall.c
SOURCES += ../config.c

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(SUBOBJDIR) -I../

CFLAGS = $(OEENCLAVE_CFLAGS)

LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libostargetsgxenclave.a
LIBS += $(LIBDIR)/libosutils.a

LDFLAGS += $(OEENCLAVE_LDFLAGS)
ifdef LIBOS_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
LDFLAGS += $(GCOV_LDFLAGS)
LIBS += $(LIBDIR)/libgcov_musl.a
endif

CLEAN = $(SUBOBJDIR)/libos_t.h $(SUBOBJDIR)/libos_t.c $(SUBOBJDIR)/libos_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/libos_t.c: ../libos.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../libos.edl
