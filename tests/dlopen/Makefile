TOP=$(abspath ../..)
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all: libos
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

ifdef STRACE
OPTS = --strace
endif

tests:
	$(RUNTEST) $(LIBOS_EXEC) rootfs /dlopen $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	$(MAKE) -C appdir clean
	rm -rf rootfs
