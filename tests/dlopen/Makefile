TOP=$(abspath ../..)
include $(TOP)/defs.mak

IMG=myst-alpine
APPDIR=$(CURDIR)/appdir

all: myst rootfs

rootfs: $(APPDIR)/dlopen
	$(BINDIR)/myst mkcpio appdir rootfs

$(APPDIR)/dlopen:
	docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"

ifdef STRACE
OPTS = --strace
endif

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /dlopen $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	$(MAKE) -C appdir clean
	rm -rf rootfs ramfs
