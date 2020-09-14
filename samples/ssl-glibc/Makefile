TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

all: libos
	$(MAKE) -C appdir clean
	$(MAKE) -C appdir
	$(BINDIR)/libos mkcpio appdir rootfs

OPTS = --strace

run-server: libos
	$(LIBOS_EXEC) $(OPTS) rootfs /ssl_server

run-client: libos
	$(LIBOS_EXEC) $(OPTS) rootfs /ssl_client1

clean:
	rm -f rootfs
	$(MAKE) -C appdir clean

libos:
	$(MAKE) -C $(TOP)/tools/libos
