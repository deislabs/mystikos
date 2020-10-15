TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = $(SUBOBJDIR)/appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos rootfs

rootfs: spawn.c child.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/spawn spawn.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/child child.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

tests: all
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/spawn $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export ramfs
