TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = image

PROGRAM = main

SOURCES = $(wildcard *.c)

INCLUDES = -I$(SUBOBJDIR) -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS)
ifdef LIBOS_ENABLE_GCOV
LDFLAGS += $(GCOV_LDFLAGS)
endif

LIBS =
LIBS += $(LIBDIR)/liboshost.a
LIBS += $(LIBDIR)/libosutils.a

REDEFINE_TESTS=1

CLEAN = ramfs rootfs

include $(TOP)/rules.mak

IMAGE = $(TOP)/build/bin/tests/elf/image/image

tests: test1 test2

test1:
	$(RUNTEST) $(SUBBINDIR)/main $(IMAGE)

test2:
	@ $(MKROOTFS) $(SUBBINDIR)/$(PROGRAM) rootfs $(IMAGE)
	@ $(RUNTEST) $(LIBOS_EXEC) rootfs /bin/$(PROGRAM) $(IMAGE)
