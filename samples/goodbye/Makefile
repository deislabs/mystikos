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

ifdef LIBOS_ENABLE_GCOV
OPTS += --export-ramfs
endif

run: all
	$(LIBOS_EXEC) $(OPTS) rootfs /goodbye

clean:
	rm -rf rootfs ramfs
	$(MAKE) -C appdir clean
