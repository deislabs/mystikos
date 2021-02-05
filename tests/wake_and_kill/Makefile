TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROG = wake_and_kill
APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: rootfs

rootfs: $(PROG).c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(PROG) $(PROG).c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/$(PROG) $(OPTS)

clean:
	rm -rf $(APPDIR) rootfs
