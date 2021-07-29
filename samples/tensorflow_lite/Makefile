TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
	OPTS = --strace
endif

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile.slim.buster

rootfs: appdir
	$(MYST) mkext2 appdir ext2rootfs

run:
	$(MYST_EXEC) $(OPTS) ext2rootfs /usr/local/bin/python3 --app-config-path config.json

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) ext2rootfs /usr/local/bin/python3  --app-config-path config.json

clean:
	rm -rf ext2rootfs appdir 