TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder
DNSSERVER = $(shell systemd-resolve --status | grep "DNS Servers" | cut -f2 -d:)

ifdef STRACE
OPTS = --strace
endif

ifdef EXPORT
OPTS = --export-rootfs
endif

all: libos rootfs

tests:
	$(RUNTEST) $(LIBOS_EXEC) $(OPTS) rootfs /curl https://www.microsoft.com 2>&1 > /dev/null

gdb: all
	$(LIBOS_GDB) --args $(LIBOS_EXEC) $(EXEC) $(OPTS) rootfs /curl https://www.microsoft.com

rootfs: libos
	$(APPBUILDER) Dockerfile
	echo "nameserver $(DNSSERVER)" >> $(APPDIR)/etc/resolv.conf
	$(BINDIR)/libos mkcpio appdir rootfs

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf rootfs export $(APPDIR)
