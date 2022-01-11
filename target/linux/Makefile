TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysttargetlinux.a

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

SOURCES += $(wildcard *.c)
SOURCES += ../shared/waitwake.c
SOURCES += ../shared/runthread.c
SOURCES += ../shared/poll.c
SOURCES += ../shared/epoll.c
SOURCES += ../shared/luks.c
SOURCES += ../shared/sha256.c
SOURCES += ../shared/verify.c
SOURCES += ../shared/nanosleep.c
SOURCES += ../shared/interrupt.c

CFLAGS = $(DEFAULT_CFLAGS)

ifdef MYST_RELEASE
CFLAGS += $(OPTIMIZATION_CFLAGS)
endif

INCLUDES = -I$(INCDIR) -I$(MBEDTLS_INCDIR) -I$(OE_INCDIR)

ifdef MYST_FUZZING
CFLAGS += \
	-Wno-varargs \
    -Wno-sometimes-uninitialized

CFLAGS += \
    -O0 -g \
	-fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-coverage=trace-pc-guard
INCLUDES += -I$(TOP)/fuzzing/src/include
DEFINES += -DMYST_FUZZING
endif

include $(TOP)/rules.mak
