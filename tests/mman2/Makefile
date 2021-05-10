TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC=gcc

PROGRAM = mman2

SOURCES = main.c ../../kernel/mman2.c

INCLUDES = -I$(INCDIR)

CFLAGS = -O3 $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	@ $(SUBBINDIR)/$(PROGRAM)

CG = valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out

cg:
	$(CG) $(SUBBINDIR)/$(PROGRAM)

ANN=cg_annotate --auto=yes cachegrind.out

ann:
	$(ANN)
