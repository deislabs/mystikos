TOP=$(abspath ../../..)
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetsgxenclave.a

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

SOURCES += $(wildcard *.c)
SOURCES += ../../shared/runthread.c
SOURCES += ../../shared/luks.c
SOURCES += ../../shared/crypto.c
SOURCES += ../../shared/sha256.c
SOURCES += ../../shared/verify.c

CFLAGS = $(OEENCLAVE_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_RELEASE
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

INCLUDES = $(OEENCLAVE_INCLUDES) -I$(INCDIR)

ifdef MYST_FUZZING
CFLAGS += \
    -O0 -g \
	-fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-address-instrument-interceptors \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-address-instrument-interceptors \
    -fsanitize-coverage=trace-pc-guard
INCLUDES += -I$(TOP)/fuzzing/src/include
DEFINES += -DMYST_FUZZING
endif

include $(TOP)/rules.mak
