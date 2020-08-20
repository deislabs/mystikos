TOP = $(abspath ../..)
SUBDIR = samples/ssl_server
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

all: libos
	$(MAKE) -C appdir clean
	$(MAKE) -C appdir
	$(BINDIR)/libos mkcpio appdir rootfs

OPTS = --strace

run-server: libos
	$(BINDIR)/libos exec $(OPTS) rootfs /ssl_server

run-server-gdb: libos
	$(BINDIR)/oegdb --args $(BINDIR)/libos exec $(OPTS) rootfs /ssl_server

run-client: libos
	$(BINDIR)/libos exec $(OPTS) rootfs /ssl_client1

run-client-gdb: libos
	$(BINDIR)/oegdb --args $(BINDIR)/libos exec $(OPTS) rootfs /ssl_client1

clean:
	rm -f rootfs
	$(MAKE) -C appdir clean

libos:
	$(MAKE) -C $(TOP)/tools/libos
