TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = mman2

SOURCES = $(wildcard *.c) ../../kernel/mman2.c

INCLUDES = -I$(INCDIR)

CFLAGS = -g -O3 $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = -g $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	@ $(SUBBINDIR)/$(PROGRAM)

CG = valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out

cg:
	$(CG) $(SUBBINDIR)/$(PROGRAM)

ann:
	cg_annotate --auto=yes -I$(TOP)/kernel -I$(CURDIR) cachegrind.out

#$(CURDIR)/mman2.c $(TOP)/kernel/mman2.c
