TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmystutils.a

SOURCES += $(wildcard *.c)
SOURCES += $(wildcard *.s)

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include
INCLUDES += -I$(BUILDDIR)/openenclave/include/openenclave/3rdparty

CFLAGS =
CFLAGS += $(DEFAULT_CFLAGS)
CFLAGS += $(OPTIMIZATION_CFLAGS)
CFLAGS += -nostdinc
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses
CFLAGS += -Wstack-usage=512

LDFLAGS = $(DEFAULT_LDFLAGS)

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

include $(TOP)/rules.mak
