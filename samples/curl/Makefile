TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all:
	docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

ifdef STRACE
OPTS = --strace
endif

ifdef EXPORT
OPTS = --export-rootfs
endif

run: all
	$(LIBOS_EXEC) $(OPTS) rootfs /curl

gdb: all
	$(LIBOS_GDB) --args $(BINDIR)/libos $(EXEC) $(OPTS) rootfs /curl

clean:
	rm -rf rootfs export
	$(MAKE) -C appdir clean
