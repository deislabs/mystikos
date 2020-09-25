TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS =
LIBS += $(LIBDIR)/liboshost.a
LIBS += $(LIBDIR)/libosutils.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests: test1 test2

test1:
	$(RUNTEST) $(SUBBINDIR)/main conf

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs conf
	@ $(RUNTEST) $(LIBOS_EXEC) rootfs /bin/$(PROGRAM) conf
