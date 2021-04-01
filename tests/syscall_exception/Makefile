TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: syscall.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/syscall_exception syscall.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/syscall_exception $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
