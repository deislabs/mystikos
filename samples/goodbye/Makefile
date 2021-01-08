TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=myst-alpine
APPDIR=$(CURDIR)/appdir

all:
	docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"
	$(BINDIR)/myst mkcpio appdir rootfs

ifdef STRACE
OPTS = --strace
endif

ifdef MYST_ENABLE_GCOV
OPTS += --export-ramfs
endif

run: all
	$(MYST_EXEC) $(OPTS) rootfs /goodbye

clean:
	rm -rf rootfs ramfs
	$(MAKE) -C appdir clean
