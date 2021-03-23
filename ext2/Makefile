TOP=$(abspath ..)
include $(TOP)/defs.mak

SUBLIBDIR=$(LIBDIR)

ARCHIVE = libmystext2.a

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR) -I$(BUILDDIR)/musl/include

CFLAGS =
CFLAGS += $(DEFAULT_CFLAGS)
CFLAGS += $(OPTIMIZATION_CFLAGS)
CFLAGS += -nostdinc
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
CFLAGS += -Wno-conversion
CFLAGS += -Wno-parentheses
CFLAGS += -O3

# ATTN: enable this!
#CFLAGS += -Wextra

LDFLAGS = $(DEFAULT_LDFLAGS)

include $(TOP)/rules.mak

k:
	$(MAKE) -C ../kernel
