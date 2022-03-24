TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = image

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)
ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS =
LIBS += $(LIBDIR)/libmysthost.a
LIBS += $(LIBDIR)/libmystutils.a

REDEFINE_TESTS=1

CLEAN = ramfs rootfs

include $(TOP)/rules.mak

IMAGE = $(TOP)/build/bin/tests/elf/image/image

tests: test1 test2

test1:
	$(RUNTEST) $(SUBBINDIR)/main $(IMAGE)

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs $(IMAGE)
	@ $(RUNTEST) $(MYST_EXEC) --strace rootfs /bin/$(PROGRAM) $(IMAGE)
