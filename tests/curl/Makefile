TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

ifdef EXPORT
OPTS += --export-rootfs
endif

all:
	$(MAKE) myst
	$(MAKE) appdir
	$(MAKE) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs --app-config-path config1.json /curl https://www.microsoft.com 2>&1 > /dev/null

gdb: all
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs --app-config-path config1.json /curl https://www.microsoft.com

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	$(BINDIR)/myst mkcpio appdir rootfs

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs export $(APPDIR)
