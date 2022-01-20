TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: linkat.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/linkat linkat.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) cpio_rootfs
	$(MYST) mkext2 $(APPDIR) ext2_rootfs

ifdef STRACE
OPTS = --strace
endif

ifdef PERF
OPTS = --perf
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) cpio_rootfs /bin/linkat $(OPTS)
	$(RUNTEST) $(MYST_EXEC) ext2_rootfs /bin/linkat $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) cpio_rootfs ext2_rootfs export ramfs
