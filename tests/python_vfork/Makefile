TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

APP_NAME=/usr/local/bin/python3
APP_ARGS=/app/test_vfork.py

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(APP_NAME) $(APP_ARGS)

gdb:
	$(MAKE) tests GDB=1

clean:
	rm -fr appdir rootfs
