TOP = $(abspath ../..)
SUBDIR = samples/curl
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all:
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/libos mkcpio appdir rootfs

#OPTS = --strace

run: all
	$(BINDIR)/libos exec $(OPTS) rootfs /curl

clean:
	rm -f rootfs
	$(MAKE) -C appdir clean
