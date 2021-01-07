TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = cpio

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS = $(LIBDIR)/libmysthost.a
LIBS = $(LIBDIR)/libmystutils.a

REDEFINE_TESTS=1

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests: test1 test2 test3 test4

test1:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/cpio cpio mem

test2:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/cpio cpio file

test3:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs cpio
	@ $(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROGRAM) cpio mem

test4:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs cpio
	@ $(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROGRAM) cpio file
