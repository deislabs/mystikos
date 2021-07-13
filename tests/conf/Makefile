TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)
ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS =
LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a

REDEFINE_TESTS=1

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests: test1 test2

test1:
	$(RUNTEST) $(SUBBINDIR)/main conf

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs conf
	@ $(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROGRAM) conf
