TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g

all: myst rootfs

rootfs: tlscert.c
	mkdir -p $(APPDIR)/
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/tlscert tlscert.c
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /tlscert $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
