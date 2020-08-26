TOP=$(abspath ../..)
SUBDIR = samples/dlopen
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all: libos
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

#OPTS = --strace

run:
	$(BINDIR)/libos exec rootfs /main $(OPTS)

gdb:
	$(OEGDB) --args $(BINDIR)/libos exec rootfs /main $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	$(MAKE) -C appdir clean
	rm -rf rootfs
