TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = fs
SOURCES = fs.c
INCLUDES =
CFLAGS = -Wall -fPIC -g $(GCOV_CFLAGS)
LDFLAGS = $(GCOV_LDFLAGS)
ROOTHASH=$(SUBOBJDIR)/roothash

ifdef MYST_ENABLE_GCOV
LDFLAGS = -lgcov
endif

ifdef STRACE
OPTS = --strace
endif

CLEAN = appdir rootfs ext2rootfs ramfs

DEPENDS = deps

include $(TOP)/rules.mak

tests: test1 test2

test1: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/fs

t: test2

test2: ext2rootfs
	$(MYST) fssig --roothash ext2rootfs > $(ROOTHASH)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2rootfs --roothash=$(ROOTHASH) /bin/fs

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

ext2rootfs: appdir
	sudo $(MYST) mkext2 appdir ext2rootfs

appdir: $(SUBBINDIR)/fs
	mkdir -p appdir/bin
	cp $(SUBBINDIR)/fs appdir/bin/fs

deps:
	$(MAKE) -C ../../kernel
