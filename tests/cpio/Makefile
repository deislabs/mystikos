.NOTPARALLEL:

TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = cpio

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)
ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS = $(LIBDIR)/libmystutils.a $(LIBDIR)/libmysthost.a

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
