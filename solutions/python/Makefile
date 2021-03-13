TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

OPTS = --user-mem-size=128m

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	$(MAKE) ext2

cpio:
	$(MYST) mkcpio appdir rootfs

ext2:
	sudo $(MYST) mkext2 -f appdir rootfs
	sudo truncate --size=-4096 rootfs

run:
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/hello_world.py

clean:
	rm -rf rootfs appdir
