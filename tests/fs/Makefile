TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = fs

SOURCES = fs.c

INCLUDES =

CFLAGS = -Wall -fPIC -g $(GCOV_CFLAGS)

LDFLAGS = $(GCOV_LDFLAGS)

ifdef LIBOS_ENABLE_GCOV
LDFLAGS = -lgcov
endif

CLEAN = rootfs ramfs

include $(TOP)/rules.mak

tests:
	$(MKROOTFS) $(SUBBINDIR)/fs rootfs
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/fs
