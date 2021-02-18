TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib -lfoo

export LD_LIBRARY_PATH=$(APPDIR)/lib

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: foo.c shlib.c
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	$(MUSL_GCC) $(CFLAGS) -shared -o $(APPDIR)/lib/libfoo.so foo.c
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/shlib shlib.c $(LDFLAGS)
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shlib $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
