TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = ext2

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS)
ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

LDFLAGS = $(OEHOST_LDFLAGS)

LIBS += $(LIBDIR)/libmystext2.a
LIBS += $(LIBDIR)/libmystutils.a
LIBS += $(LIBDIR)/libmysthost.a

include $(TOP)/rules.mak

EXT2FS=$(SUBOBJDIR)/ext2fs
MNT=$(SUBOBJDIR)/mnt
LOOP=$(SUBOBJDIR)/loop

ifeq ($(USE_CALLGRIND),1)
PREFIX=valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out
endif

ifeq ($(USE_GDB),1)
PREFIX=gdb --args
endif

EXT2FS_SIZE=536870912

tests:
	mkdir -p $(SUBOBJDIR)
	$(MYST) mkext2 --force --size=$(EXT2FS_SIZE) ext2dir $(EXT2FS)
	$(PREFIX) $(RUNTEST) $(PREFIX) $(SUBBINDIR)/ext2 $(EXT2FS)

cachegrind:
	mkdir -p $(SUBOBJDIR)
	$(MYST) mkext2 --force --size=$(EXT2FS_SIZE) ext2dir $(EXT2FS)
	$(CACHEGRIND_COMMAND) $(SUBBINDIR)/ext2 $(EXT2FS)

ann:
	cg_annotate --auto=yes -I$(TOP)/ext2 cachegrind.out

loop:
	cat $(LOOP)
