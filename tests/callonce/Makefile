TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPDIR = appdir

all: rootfs

rootfs: appdir
	$(MYST) mkcpio $(APPDIR) rootfs

appdir:
	$(APPBUILDER) Dockerfile

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /app/call-once $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs
