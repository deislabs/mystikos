TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = strtonum

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)
ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a

REDEFINE_TESTS=1

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests: test1 test2

test1:
	$(RUNTEST) $(PREFIX) $(SUBBINDIR)/$(PROGRAM)

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs
	@ $(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROGRAM)
