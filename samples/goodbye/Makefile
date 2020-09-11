TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all:
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

ifdef STRACE
OPTS = --strace
endif

run: all
	$(BINDIR)/libos exec $(OPTS) rootfs /goodbye

clean:
	rm -f rootfs
	$(MAKE) -C appdir clean
