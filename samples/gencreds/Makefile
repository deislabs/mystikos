SUBDIR = samples/gencreds
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/gencreds gencreds.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

#OPTS += --strace

GDB = $(BINDIR)/oegdb

#export AZDCAP_DEBUG_LOG_LEVEL=0

run: all
	$(LIBOS) exec rootfs /bin/gencreds $(OPTS)

gdb: all
	$(GDB) --args $(LIBOS) exec rootfs /bin/gencreds $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs
