TOP=$(abspath ../../..)
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetsgxhost.a

SOURCES += ../../shared/waitwake.c
SOURCES += ../../shared/nanosleep.c
SOURCES += ../../shared/poll.c
SOURCES += ../../shared/epoll.c
SOURCES += ../../shared/interrupt.c

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef MYST_RELEASE
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

INCLUDES = -I$(INCDIR)

ifdef MYST_FUZZING
CFLAGS += \
    -fsanitize=fuzzer,address \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=fuzzer,address \
    -fsanitize-coverage=trace-pc-guard
endif

include $(TOP)/rules.mak
