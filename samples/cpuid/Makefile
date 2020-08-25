SUBDIR = samples/cpuid
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/cpuid cpuid.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

GDB = $(BINDIR)/oegdb

run: all
	$(LIBOS) exec rootfs /bin/cpuid $(OPTS)

gdb: all
	$(GDB) --args $(LIBOS) exec rootfs /bin/cpuid $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs
