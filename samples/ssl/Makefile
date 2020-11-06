TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all: libos
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

#OPTS=--strace

# ATTN: does not work: do not use
run-ssl: libos
	$(LIBOS_EXEC) $(OPTS) rootfs /ssl

run-server: libos
	$(LIBOS_EXEC) $(OPTS) rootfs /ssl_server

run-client: libos
	$(LIBOS_EXEC) $(OPTS) rootfs /ssl_client1

clean:
	rm -rf rootfs export
	$(MAKE) -C appdir clean

ls:
	sudo docker image ls | grep libos

extract:
	sudo docker save -o img.tar libos-alpine

libos:
	$(MAKE) -C $(TOP)/tools/libos
