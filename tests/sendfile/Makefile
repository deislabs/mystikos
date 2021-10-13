TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -fPIC -I$(TOP)/include -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
MEGABYTE=1048576

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: sendfile.c server.c client.c
	mkdir -p appdir/bin
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/sendfile sendfile.c server.c client.c $(LDFLAGS)
	head -c $(MEGABYTE) /dev/urandom > appdir/bigfile
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/sendfile $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf appdir rootfs export ramfs
