TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = fs
SOURCES = fs.c
INCLUDES =
CFLAGS = -Wall -fPIC -g

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef STRACE
OPTS = --strace
endif

HOSTFS = $(CURDIR)/hostfs

CLEAN = appdir rootfs ext2rootfs ramfs $(HOSTFS)

include $(TOP)/rules.mak

tests: program
	$(MAKE) test1
	$(MAKE) test2
	$(MAKE) test3
	$(MAKE) test1 FORK=fork
	$(MAKE) test2 FORK=fork
	$(MAKE) test3 FORK=fork

test1: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/fs ramfs $(FORK)

test2: ext2rootfs
ifdef MYST_ENABLE_EXT2FS
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2rootfs /bin/fs ext2fs $(FORK)
endif

test3: appdir
ifdef MYST_ENABLE_HOSTFS
	rm -rf $(HOSTFS)
	cp -r appdir $(HOSTFS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(HOSTFS) /bin/fs hostfs $(FORK)
endif

rootfs: appdir $(SUBBINDIR)/fs fs.c
	$(MYST) mkcpio appdir rootfs

ext2rootfs: appdir appdir $(SUBBINDIR)/fs fs.c
	$(MYST) mkext2 --force appdir ext2rootfs

appdir: $(SUBBINDIR)/fs fs.c
	mkdir -p appdir/bin
	cp $(SUBBINDIR)/fs appdir/bin/fs

t:
	$(MAKE) test1 FORK=fork
