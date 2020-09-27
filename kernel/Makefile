TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)
SUBBINDIR=$(LIBDIR)

PROGRAM = liboskernel.so

SOURCES = $(wildcard *.c) $(wildcard ../shared/*.c) $(wildcard *.s)

INCLUDES = -I$(INCDIR) $(OEENCLAVE_INCLUDES) -I$(BUILDDIR)/include

LDFLAGS =
LDFLAGS += -nostdlib
LDFLAGS += -nodefaultlibs
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,--no-undefined
LDFLAGS += -Wl,-Bstatic
LDFLAGS += -Wl,-Bsymbolic
LDFLAGS += -Wl,--export-dynamic
LDFLAGS += -Wl,-pie
LDFLAGS += -Wl,--build-id
LDFLAGS += -Wl,-z,noexecstack
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-gc-sections
LDFLAGS += -Wl,-elibos_enter_kernel
LDFLAGS += -Wl,--whole-archive

LIBS = $(LIBDIR)/libosutils.a

ifdef LIBOS_ENABLE_HOST_THREADS
DEFINES += -DLIBOS_ENABLE_HOST_THREADS
endif

ifdef LIBOS_USE_THREAD_STACK
DEFINES += -DLIBOS_USE_THREAD_STACK
endif

ifdef LIBOS_ENABLE_LEAK_CHECKER
DEFINES += -DLIBOS_ENABLE_LEAK_CHECKER
endif

CFLAGS = $(OEENCLAVE_CFLAGS) -O0

ifdef LIBOS_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
DEFINES += -DLIBOS_ENABLE_GCOV
endif

include $(TOP)/rules.mak
