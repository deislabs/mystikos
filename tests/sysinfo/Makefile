TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROG = sysinfo
APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: $(PROG).c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(PROG) $(PROG).c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROG) $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
