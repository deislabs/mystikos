TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g -I$(TOP)/include/ $(OEENCLAVE_INCLUDES)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: tlscert.c
	mkdir -p $(APPDIR)/
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/tlscert tlscert.c
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs --app-config-path config.json /tlscert $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
