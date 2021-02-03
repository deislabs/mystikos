TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: myst rootfs

rootfs: hostfs.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hostfs hostfs.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

HOSTDIR=$(SUBOBJDIR)

tests: all
	rm -rf $(HOSTDIR)
	mkdir -p $(HOSTDIR)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/hostfs $(HOSTDIR)

ls:
	ls -l $(HOSTDIR)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(HOSTDIR) rootfs export ramfs
