TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS = --strace
endif

all: libos
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/cpuid cpuid.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

tests:
	$(LIBOS) $(EXEC) $(OPTS) rootfs /bin/cpuid $(OPTS)

gdb:
	$(LIBOS_GDB) --args $(LIBOS) $(EXEC) $(OPTS) rootfs /bin/cpuid $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export ramfs
