TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib

export LD_LIBRARY_PATH=$(APPDIR)/lib

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: nbio.c
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/nbio nbio.c $(LDFLAGS)
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/nbio $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
