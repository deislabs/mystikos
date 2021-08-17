TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: getmempolicy.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/getmempolicy getmempolicy.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

ifdef PERF
OPTS = --perf
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/getmempolicy $(OPTS)

native:
	gcc $(CFLAGS) getmempolicy.c $(LDFLAGS) -L. -lnuma
	./a.out

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
