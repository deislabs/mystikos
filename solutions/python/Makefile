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
	$(MYST) mkcpio appdir rootfs
run:
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/hello_world.py

clean:
	rm -rf rootfs appdir
