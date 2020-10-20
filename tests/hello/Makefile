TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos rootfs

rootfs: hello.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/hello red green blue $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export ramfs
