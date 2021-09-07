TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

run:
	$(MYST_EXEC) $(OPTS) rootfs /usr/sbin/nginx --app-config-path config.json

clean:
	rm -rf rootfs appdir
