TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

build: rootfs

appdir:
	$(APPBUILDER) -i hullcritical/dotnet-library-test:release-ubuntu

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

run:
	$(MYST_EXEC) $(OPTS) rootfs /bin/echo --app-config-path config.json

clean:
	rm -rf appdir rootfs