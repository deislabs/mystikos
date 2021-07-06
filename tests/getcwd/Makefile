TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

DEFLATE=1

ifdef DEFLATE
MKCPIO_OPTS = --deflate
endif

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: getcwd.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/getcwd getcwd.c $(LDFLAGS)
	$(MYST) mkcpio $(MKCPIO_OPTS) $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/getcwd $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
