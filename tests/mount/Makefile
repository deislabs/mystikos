TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = mount

SOURCES = mount.c

INCLUDES =

CFLAGS = -Wall -fPIC -g $(GCOV_CFLAGS)

LDFLAGS = $(GCOV_LDFLAGS)

ifdef MYST_ENABLE_GCOV
LDFLAGS = -lgcov
endif

ifdef STRACE
OPTS += --strace
endif

CLEAN = appdir rootfs ramfs

include $(TOP)/rules.mak

tests:
	rm -rf appdir
	rm -rf rootfs
	$(MKROOTFS) $(SUBBINDIR)/mount rootfs
	$(MYST) excpio rootfs appdir
	$(MYST) mkcpio datafs appdir/datafs
	mkdir -p appdir/mnt/datafs
	$(MYST) mkcpio appdir rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/mount
