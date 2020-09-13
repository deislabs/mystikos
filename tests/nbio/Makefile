TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib

export LD_LIBRARY_PATH=$(APPDIR)/lib

all: libos
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/nbio nbio.c $(LDFLAGS)
	$(LIBOS) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	$(LIBOS) $(EXEC) $(OPTS) rootfs /bin/nbio $(OPTS)

gdb:
	$(LIBOS_GDB) --args $(LIBOS) $(EXEC) rootfs /bin/nbio $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export ramfs
