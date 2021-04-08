TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -Wall -g -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: robust.c
	mkdir -p appdir/bin
	$(MUSL_GCC) $(CFLAGS) -o appdir/bin/robust robust.c $(LDFLAGS)
	$(MYST) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=512m

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/robust

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs appdir
