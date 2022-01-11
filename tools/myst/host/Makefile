TOP=$(abspath ../../..)
SUBBINDIR = $(TOP)/build/bin
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

PROGRAM = myst

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

SOURCES =
SOURCES += $(SUBOBJDIR)/myst_u.c
SOURCES += $(wildcard *.c)
SOURCES += $(wildcard mkext2/*.c)
SOURCES += $(wildcard ../*.c)

INCLUDES = $(OEHOST_INCLUDES) -I$(SUBOBJDIR) -I$(INCDIR) -I../

CFLAGS = $(OEHOST_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_ENABLE_ZERO_BASE_ENCLAVES
DEFINES += -DMYST_ENABLE_ZERO_BASE_ENCLAVES
endif

LDFLAGS = $(OEHOST_LDFLAGS)
LDFLAGS += -lcrypto

ifndef MYST_FUZZING
ifdef MYST_ENABLE_ZERO_BASE_ENCLAVES
# Load the host program at 1TB
LDFLAGS += -Wl,-Ttext-segment,0x10000000000
endif
endif

LIBS += $(OEHOST_LIBDIR)/liboehost.a
LIBS += $(OEHOST_LIBDIR)/liboesign.a
LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libmysthost.a
LIBS += $(LIBDIR)/libmysttargetcommon.a
LIBS += $(LIBDIR)/libmysttargetlinux.a
LIBS += $(LIBDIR)/libmysttargetsgxhost.a
LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(MBEDTLS_LIBS)

CFLAGS += -Wno-unused-function

ifdef MYST_FUZZING
CFLAGS += \
    -Wno-sometimes-uninitialized \
    -Wno-missing-braces \
    -Wno-unused-function \
    -Wno-incompatible-pointer-types-discards-qualifiers \
    -Wno-implicit-function-declaration
DEFINES += -DMYST_FUZZING
INCLUDES += -I$(TOP)/fuzzing/src/include
SOURCES += $(TOP)/fuzzing/src/targets/fuzz-exec-linux.c
CFLAGS += \
    -O0 -g \
    -fsanitize=fuzzer,address \
    -fsanitize-coverage=edge,indirect-calls,no-prune \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=fuzzer,address \
    -fsanitize-coverage=edge,indirect-calls,no-prune \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += -mno-relax
LIBS += $(BUILDDIR)/myst_fuzzing/output/lib/libfuzzsup_host.a
LIBS += $(BUILDDIR)/myst_fuzzing/output/lib/libfuzzsup_tcall.a
endif

ifdef MYST_ENABLE_GCOV
LIBS += $(LIBDIR)/libmystgcovserver.a
endif

CLEAN = $(SUBOBJDIR)/myst_u.h $(SUBOBJDIR)/myst_u.c $(SUBOBJDIR)/myst_args.h

include $(TOP)/rules.mak

EDGER8R_OPTS += --untrusted
EDGER8R_OPTS += --search-path $(OE_INCDIR)
EDGER8R_OPTS += --untrusted-dir $(SUBOBJDIR)

ifdef MYST_FUZZING
EDGER8R_OPTS += "-DMYST_FUZZING_ENC"
endif

$(SUBOBJDIR)/myst_u.c: ../myst.edl
	$(EDGER8R) $(EDGER8R_OPTS) ../myst.edl --search-path ../
