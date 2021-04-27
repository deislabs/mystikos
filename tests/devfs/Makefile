TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS += --strace
endif

all: myst rootfs

rootfs: devfs.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/devfs devfs.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/devfs $(OPTS)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs /bin/devfs $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
