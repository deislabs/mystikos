TOP=$(abspath ../..)
include $(TOP)/defs.mak
APPDIR = appdir
CFLAGS = -fPIC -I$(TOP)/include -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) rootfs

# server.c client.c

rootfs: ppoll.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/ppoll ppoll.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs
ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/ppoll $(OPTS)

clean:
	rm -rf $(APPDIR) rootfs export ramfs