TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs:
	mkdir -p $(APPDIR)
	$(CC) $(CFLAGS) -o $(APPDIR)/main main.c -lpthread
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS = --strace
endif

__tests:
	$(MYST_EXEC) rootfs /main $(OPTS); test "$$?" -eq "134"

tests: all
	$(RUNTEST) $(MAKE) __tests

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
