SUBDIR = samples/pthread
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/pthread pthread.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

run: all
	$(LIBOS) exec $(OPTS) rootfs /bin/pthread

gdb: all
	$(OEGDB) --args $(LIBOS) exec rootfs /bin/pthread $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs

gdb-core:
	$(OEGDB) core
