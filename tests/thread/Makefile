TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
CC = $(MUSL_GCC)

all: libos
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/thread thread.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	$(LIBOS) exec $(OPTS) rootfs /bin/thread

gdb:
	$(LIBOS_GDB) --args $(LIBOS) exec rootfs /bin/thread $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export
