TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

SUBBINDIR=$(BINDIR)

PROGRAM = syscall

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

LIBS = $(LIBDIR)/libmystutils.a

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

REDEFINE_TESTS=1

ifdef MYST_FUZZING
DEFINES += -DMYST_FUZZING
CFLAGS += \
    -fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-coverage=trace-pc-guard
endif

include $(TOP)/rules.mak
