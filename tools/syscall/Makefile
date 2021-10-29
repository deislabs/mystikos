TOP=$(abspath ../..)
include $(TOP)/defs.mak

SUBBINDIR=$(BINDIR)

PROGRAM = syscall

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

LIBS = $(LIBDIR)/libmystutils.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak
