TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: vfork.c child.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/vfork vfork.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/child child.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

ifdef PERF
OPTS += --perf
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/vfork $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
