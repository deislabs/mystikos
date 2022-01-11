TOP=$(abspath ..)
include $(TOP)/defs.mak

ifdef MYST_FUZZING
CC=${BUILDDIR}/oe-llvm-2.0/bin/clang
CXX=${BUILDDIR}/oe-llvm-2.0/bin/clang++
endif

SUBLIBDIR=$(LIBDIR)
SUBBINDIR=$(LIBDIR)

PROGRAM = libmystkernel.so

SOURCES = $(wildcard *.c)
SOURCES += ../asm/setjmp.s
SOURCES += ../asm/longjmp.s
SOURCES += ../asm/jump.s

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include

# include <myst/deprecations.h> first in every source.
INCLUDES += -include $(INCDIR)/myst/deprecations.h

DEFINES = $(MYST_DEFINES)

ifeq ($(MYST_ENABLE_HOSTFS),1)
DEFINES += -DMYST_ENABLE_HOSTFS
endif

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

ifdef MYST_RELEASE
DEFINES += -DMYST_RELEASE
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
WARNINGS += -Winit-self
ifndef MYST_FUZZING
WARNINGS += -Wstack-usage=512
endif
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
CFLAGS += $(GCOV_CFLAGS)
endif

#CFLAGS += -Wconversion

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

LIBS += $(LIBDIR)/libjson.a

LIBS += $(LIBDIR)/libmystutils.a

ifdef MYST_ENABLE_GCOV
LIBS += $(LIBDIR)/libmystgcov.a
LIBS += $(LIBDIR)/libmystgcovclient.a
endif

ifdef MYST_FUZZING
CFLAGS += \
    -Winit-self \
    -Wno-sometimes-uninitialized \
    -Wno-null-pointer-arithmetic \
    -Wno-unknown-pragmas \
    -Wno-unused-command-line-argument \
    -Wno-self-assign \
    -Wno-implicit-function-declaration \
    -Wno-unused-function \
    -Wno-pointer-arith \
    -Wno-unused-variable \
    -Wno-int-to-pointer-cast \
    -Wno-compare-distinct-pointer-types \
    -Wno-unused-parameter \
    -Wno-sign-compare
DEFINES += -DMYST_FUZZING

INCLUDES += -I$(TOP)/fuzzing/src/include
CFLAGS += \
    -O0 -g \
	-fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-address-instrument-interceptors \
    -fsanitize-coverage=trace-pc-guard
LDFLAGS += \
    -fsanitize=enclavefuzzer,enclaveaddress \
    -fsanitize-address-instrument-interceptors \
    -fsanitize-coverage=trace-pc-guard
LIBS += $(BUILDDIR)/myst_fuzzing/output/lib/libfuzzsup_kernel.a
LIBS += $(BUILDDIR)/openenclave/lib/openenclave/enclave/liboelibcxx.a
LIBS += $(BUILDDIR)/musl/lib/libc.a
endif


include $(TOP)/rules.mak

size:
	size $(LIBDIR)/libmystkernel.so

sizes:
	@ $(foreach i, $(__OBJECTS), size $(i) $(NL) )
