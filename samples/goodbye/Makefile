TOP = $(abspath ../..)
SUBDIR = samples/goodbye
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all:
	docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

run: all
	$(BINDIR)/libos exec rootfs /goodbye

clean:
	rm -f rootfs
	$(MAKE) -C appdir clean
