TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmysthostfs.a

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include

ifdef MYST_ENABLE_HOSTFS
DEFINES += -DMYST_ENABLE_HOSTFS
endif

CFLAGS =
CFLAGS += $(DEFAULT_CFLAGS)
CFLAGS += $(OPTIMIZATION_CFLAGS)
CFLAGS += -nostdinc
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses
CFLAGS += -O3

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(DEFAULT_LDFLAGS)

include $(TOP)/rules.mak
