SUBDIR = samples/shlib
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib -lfoo

export LD_LIBRARY_PATH=$(APPDIR)/lib

all: libos
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	$(MUSL_GCC) $(CFLAGS) -shared -o $(APPDIR)/lib/libfoo.so foo.c
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/main main.c $(LDFLAGS)
	$(LIBOS) mkcpio appdir rootfs

OPTS = --strace

run: all
	$(LIBOS) exec rootfs /bin/main $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs
