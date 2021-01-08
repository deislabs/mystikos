TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = strings

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS = $(LIBDIR)/libmysthost.a
LIBS = $(LIBDIR)/libmystutils.a

REDEFINE_TESTS=1

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests: test1 test2

test1:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/strings

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs
	@ $(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROGRAM)
