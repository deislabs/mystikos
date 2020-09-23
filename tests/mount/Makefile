TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = mount

SOURCES = mount.c

INCLUDES =

CFLAGS = -Wall -fPIC -g $(GCOV_CFLAGS)

LDFLAGS = $(GCOV_LDFLAGS)

ifdef LIBOS_ENABLE_GCOV
LDFLAGS = -lgcov
endif

ifdef STRACE
OPTS += --strace
endif

CLEAN = appdir rootfs

include $(TOP)/rules.mak

tests:
	rm -rf appdir
	rm -rf rootfs
	$(MKROOTFS) $(SUBBINDIR)/mount rootfs
	$(LIBOS) excpio rootfs appdir
	$(LIBOS) mkcpio datafs appdir/datafs
	mkdir -p appdir/mnt/datafs
	$(LIBOS) mkcpio appdir rootfs
	$(RUNTEST) $(LIBOS_EXEC) $(OPTS) rootfs /bin/mount
