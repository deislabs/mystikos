TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

TARGET = sgx
EXEC = exec-$(TARGET)

all: libos
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

run-server: libos
	$(BINDIR)/libos $(EXEC) $(OPTS) rootfs /ssl_server

run-server-gdb: libos
	$(LIBOS_GDB) --args $(BINDIR)/libos $(EXEC) $(OPTS) rootfs /ssl_server

run-client: libos
	$(BINDIR)/libos $(EXEC) $(OPTS) rootfs /ssl_client1

clean:
	rm -rf rootfs export
	$(MAKE) -C appdir clean

ls:
	sudo docker image ls | grep libos

extract:
	sudo docker save -o img.tar libos-alpine

libos:
	$(MAKE) -C $(TOP)/tools/libos
