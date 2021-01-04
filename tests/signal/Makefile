TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

#OPTS = --strace

all: libos rootfs

rootfs: signal.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/signal signal.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(LIBOS_EXEC) rootfs /signal $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export ramfs
