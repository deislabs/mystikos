TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

EFFECTIVE_UID = $(shell id -u)
EFFECTIVE_GID = $(shell id -g)
ETC_RESOLV_UID=$(shell stat -L /etc/resolv.conf --format "%u")
ETC_RESOLV_GID=$(shell stat -L /etc/resolv.conf --format "%g")
OPTS += --host-to-enc-uid-map $(EFFECTIVE_UID):0,$(ETC_RESOLV_UID):$(ETC_RESOLV_UID)
OPTS += --host-to-enc-gid-map $(EFFECTIVE_GID):0,$(ETC_RESOLV_GID):$(ETC_RESOLV_GID)

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
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --mount /etc/resolv.conf=/etc/resolv.conf rootfs --app-config-path config1.json /curl https://www.microsoft.com 2>&1 > /dev/null

gdb: all
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --mount /etc/resolv.conf=/etc/resolv.conf rootfs --app-config-path config1.json /curl https://www.microsoft.com

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	$(BINDIR)/myst mkcpio appdir rootfs

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs export $(APPDIR)
