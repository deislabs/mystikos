TOP=$(abspath ..)
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmystutils.a

SOURCES += $(wildcard *.c)
SOURCES += ../asm/callonstack.s

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include
INCLUDES += -I$(BUILDDIR)/openenclave/include/openenclave/3rdparty

# include <myst/deprecations.h> first in every source.
INCLUDES += -include $(INCDIR)/myst/deprecations.h

CFLAGS =
CFLAGS += $(DEFAULT_CFLAGS)
ifdef __GNUC__
CFLAGS += -nostdinc
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
endif
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-command-line-argument
ifndef MYST_FUZZING
CFLAGS += -Wstack-usage=512
endif
CFLAGS += -O3

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(DEFAULT_LDFLAGS)

ifdef MYST_FUZZING
DEFINES += -DMYST_FUZZING
CFLAGS += \
    -O0 -g \
	-fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-address-instrument-interceptors \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-address-instrument-interceptors \
    -fsanitize-coverage=trace-pc-guard
endif

include $(TOP)/rules.mak
