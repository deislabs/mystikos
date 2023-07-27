.NOTPARALLEL:
TOP=$(abspath ../../..)
SUBBINDIR=$(TOP)/build/lib/openenclave
include $(TOP)/defs.mak

PROGRAM = mystenc.so

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

ifdef MYST_ENABLE_ZERO_BASE_ENCLAVES
DEFINES += -DMYST_ENABLE_ZERO_BASE_ENCLAVES
endif

SOURCES += $(SUBOBJDIR)/myst_t.c
SOURCES += enc.c
SOURCES += clock.c
SOURCES += syscall.c
SOURCES += ../config.c
SOURCES += ../common.c
SOURCES += ../kargs.c
SOURCES += ../options.c

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

ifeq ($(MYST_OE_CRYPTO), openssl_3)
# The following workaround can be removed once internal crypto
# implementation is ported to use OpenSSL
LDFLAGS += -lmbedx509
LDFLAGS += -lmbedcrypto
LDFLAGS += -loecore
else ifeq ($(MYST_OE_CRYPTO), mbedtls)
# Support OpenSSL-based sha256 implementation
LDFLAGS += -lopensslcrypto
else
$(error "unsupported MYST_OE_CRYPTO: $(MYST_OE_CRYPTO)")
endif

CLEAN = $(SUBOBJDIR)/myst_t.h $(SUBOBJDIR)/myst_t.c $(SUBOBJDIR)/myst_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --trusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --trusted-dir $(SUBOBJDIR)

$(SUBOBJDIR)/myst_t.c: ../myst.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../myst.edl
