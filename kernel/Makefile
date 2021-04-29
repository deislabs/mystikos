TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)
SUBBINDIR=$(LIBDIR)

PROGRAM = libmystkernel.so

SOURCES = $(wildcard *.[cs])

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include

DEFINES = $(MYST_DEFINES)

ifdef MYST_NO_RECVMSG_MITIGATION
DEFINES += -DMYST_NO_RECVMSG_MITIGATION
endif

ifeq ($(MYST_ENABLE_HOSTFS),1)
DEFINES += -DMYST_ENABLE_HOSTFS
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
WARNINGS += -Wstack-usage=512

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

ifdef MYST_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
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
LDFLAGS += -Wl,-emyst_enter_kernel

ifdef MYST_ENABLE_EXT2FS
LIBS += $(LIBDIR)/libmystext2.a
endif

ifdef MYST_ENABLE_HOSTFS
LIBS += $(LIBDIR)/libmysthostfs.a
endif

LIBS += $(LIBDIR)/libmystutils.a

ifdef MYST_ENABLE_GCOV
LIBS += $(LIBDIR)/libgcov_musl.a
endif

include $(TOP)/rules.mak

size:
	size $(LIBDIR)/libmystkernel.so

sizes:
	@ $(foreach i, $(__OBJECTS), size $(i) $(NL) )
