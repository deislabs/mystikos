TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = string

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS = $(LIBDIR)/liboshost.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests: test1 test2

test1:
	$(RUNTEST) $(SUBBINDIR)/string

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs
	@ $(RUNTEST) $(LIBOS_EXEC) rootfs /bin/$(PROGRAM)
