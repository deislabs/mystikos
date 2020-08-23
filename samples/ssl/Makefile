TOP = $(abspath ../..)
SUBDIR = samples/ssl_server
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all: libos
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

OPTS += --strace
#OPTS += --real-syscalls

run-server: libos
	$(BINDIR)/libos exec $(OPTS) rootfs /ssl_server

run-server-gdb: libos
	$(BINDIR)/oegdb --args $(BINDIR)/libos exec $(OPTS) rootfs /ssl_server

run-client: libos
	$(BINDIR)/libos exec $(OPTS) rootfs /ssl_client1

clean:
	rm -f rootfs
	$(MAKE) -C appdir clean

ls:
	sudo docker image ls | grep libos

extract:
	sudo docker save -o img.tar libos-alpine

libos:
	$(MAKE) -C $(TOP)/tools/libos
