.NOTPARALLEL:
TOP=$(abspath ../../..)
SUBBINDIR=$(TOP)/build/lib/openenclave
include $(TOP)/defs.mak

PROGRAM = mystenc.so

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

DEFINES = -DUSE_ZERO_BASE_ENCLAVES

SOURCES += $(SUBOBJDIR)/myst_t.c
SOURCES += enc.c
SOURCES += clock.c
SOURCES += syscall.c
SOURCES += ../config.c
SOURCES += ../common.c
SOURCES += ../kargs.c

ifdef MYST_ENABLE_GCOV
SOURCES += gcov.c
endif

ifdef MYST_ENABLE_HOSTFS
DEFINES += -DMYST_ENABLE_HOSTFS
endif

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(SUBOBJDIR) -I../

CFLAGS = $(OEENCLAVE_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libmysttargetsgxenclave.a
LIBS += $(LIBDIR)/libmystutils.a

ifdef MYST_ENABLE_GCOV
LIBS += $(LIBDIR)/libmystgcov.a
LIBS += $(LIBDIR)/libmystgcovclient.a
endif

LDFLAGS += $(OEENCLAVE_LDFLAGS)
LDFLAGS += -lcrypto

CLEAN = $(SUBOBJDIR)/myst_t.h $(SUBOBJDIR)/myst_t.c $(SUBOBJDIR)/myst_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/myst_t.c: ../myst.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../myst.edl
