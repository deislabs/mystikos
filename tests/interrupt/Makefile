TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -I$(TOP)/include
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) rootfs

rootfs: interrupt.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/interrupt interrupt.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

ifdef PERF
OPTS = --perf
endif

OPTS += --user-mem-size=8m

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/interrupt $(OPTS)

clean:
	rm -rf $(APPDIR) rootfs export ramfs

t:
	$(MAKE) tests TARGET=linux
