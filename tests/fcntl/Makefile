TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

all: myst rootfs

rootfs: $(APPDIR)/test
	$(BINDIR)/myst mkcpio appdir rootfs

$(APPDIR)/test:
	mkdir -p $(APPDIR)
	gcc -g -o $(APPDIR)/test test_fcntl.c

ifdef STRACE
OPTS = --strace
endif

tests:
	$(MYST_EXEC) rootfs /test $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs ramfs appdir
