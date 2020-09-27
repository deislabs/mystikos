TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)
SUBBINDIR=$(LIBDIR)

PROGRAM = liboskernel.so

SOURCES = $(wildcard *.[cs])

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/host-musl/include

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

CFLAGS =
CFLAGS += -g
CFLAGS += -Os
CFLAGS += -nostdinc
CFLAGS += -m64
CFLAGS += -fPIC
CFLAGS += -ftls-model=local-exec
CFLAGS += -fstack-protector-strong
CFLAGS += -fno-omit-frame-pointer
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
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
LDFLAGS += -Wl,-gc-sections
LDFLAGS += -Wl,-elibos_enter_kernel

LIBS =
LIBS += $(LIBDIR)/libosutils.a

include $(TOP)/rules.mak

size:
	size $(LIBDIR)/liboskernel.so
