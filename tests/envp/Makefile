TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

export UUID_051005DCD0B0448AAD4746E8538F4D81=12345

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: envp.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/envp envp.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/envp $(TARGET)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
