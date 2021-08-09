TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g -I$(INCDIR)
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS += --strace
endif

all: myst rootfs

rootfs: procfs.c maps.c ../../host/maps.c
	mkdir -p $(APPDIR)/bin
	gcc $(CFLAGS) -c procfs.c maps.c
	gcc $(CFLAGS) -o $(APPDIR)/bin/procfs procfs.o maps.o $(LDFLAGS)
	truncate --size=1m $(APPDIR)/datafile
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/procfs $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
