TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBBINDIR=$(BINDIR)

PROGRAM = syscall

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

LIBS = $(LIBDIR)/libmystutils.a

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

REDEFINE_TESTS=1

include $(TOP)/rules.mak
