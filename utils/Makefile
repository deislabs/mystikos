TOP=$(abspath ..)
include $(TOP)/defs.mak

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
CFLAGS += $(OPTIMIZATION_CFLAGS)
CFLAGS += -nostdinc
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses
CFLAGS += -Wstack-usage=512
CFLAGS += -O3

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(DEFAULT_LDFLAGS)

include $(TOP)/rules.mak
