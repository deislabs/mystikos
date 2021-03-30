TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = $(SUBOBJDIR)/appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: spawnfa.c child.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/spawnfa spawnfa.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/child child.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/spawnfa $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
