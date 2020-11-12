TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos rootfs

rootfs: sockets.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/sockets sockets.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

UDSPATH=$(OBJDIR)/uds

tests: all
	rm -rf $(UDSPATH)
	$(RUNTEST) $(LIBOS_EXEC) rootfs /bin/sockets $(UDSPATH) $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export ramfs

ls:
	ls $(UDSPATH)
