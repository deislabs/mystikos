TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

sec = $(shell date +%s)
nsec = $(shell date +%N)

all: myst
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -g -o $(APPDIR)/bin/clock main.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/clock  $(sec) $(nsec) $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs ramfs
