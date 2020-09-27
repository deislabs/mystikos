TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)
SUBBINDIR=$(LIBDIR)

PROGRAM = liboskernel.so

SOURCES = $(wildcard *.c) $(wildcard *.s)

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/host-musl/include

ifdef LIBOS_USE_THREAD_STACK
DEFINES += -DLIBOS_USE_THREAD_STACK
endif

ifdef LIBOS_ENABLE_LEAK_CHECKER
DEFINES += -DLIBOS_ENABLE_LEAK_CHECKER
endif

CFLAGS = $(OEENCLAVE_CFLAGS) -O0

# suppress conversion errors in musl lib headers
CFLAGS = -Wno-conversion

ifdef LIBOS_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
DEFINES += -DLIBOS_ENABLE_GCOV
endif

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
#LDFLAGS += -Wl,--whole-archive

LIBS = $(LIBDIR)/libosutils.a

include $(TOP)/rules.mak

size:
	size $(LIBDIR)/liboskernel.so
