TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)
SUBBINDIR=$(LIBDIR)

PROGRAM = liboskernel.so

SOURCES = $(wildcard *.[cs])

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include

ifdef LIBOS_USE_THREAD_STACK
DEFINES += -DLIBOS_USE_THREAD_STACK
endif

ifdef LIBOS_ENABLE_LEAK_CHECKER
DEFINES += -DLIBOS_ENABLE_LEAK_CHECKER
endif

WARNINGS =
WARNINGS += -Wall
WARNINGS += -Werror
WARNINGS += -Wpointer-arith
WARNINGS += -Wconversion
WARNINGS += -Wextra
WARNINGS += -Wno-missing-field-initializers
WARNINGS += -Wno-type-limits
WARNINGS += -Wno-conversion

# ATTN: this optimization makes little difference for the kernel
#USE_GC_SECTIONS=1

CFLAGS =
CFLAGS += -g
CFLAGS += $(OPTIMIZATION_CFLAGS)
CFLAGS += -nostdinc
CFLAGS += -m64
CFLAGS += -fPIC
CFLAGS += -ftls-model=local-exec
CFLAGS += -fstack-protector-strong
CFLAGS += -fno-omit-frame-pointer
ifdef USE_GC_SECTIONS
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
endif
CFLAGS += $(WARNINGS)

# suppress conversion errors in musl lib headers
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses

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
ifdef USE_GC_SECTIONS
LDFLAGS += -Wl,-gc-sections
endif
LDFLAGS += -Wl,-elibos_enter_kernel

LIBS += $(LIBDIR)/libosutils.a

ifdef LIBOS_ENABLE_GCOV
LIBS += $(LIBDIR)/libgcov_musl.a
endif

include $(TOP)/rules.mak

size:
	size $(LIBDIR)/liboskernel.so

sizes:
	@ $(foreach i, $(__OBJECTS), size $(i) $(NL) )
