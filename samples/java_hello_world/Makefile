TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
	OPTS = --strace
endif

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkext2 appdir ext2rootfs

run:
	$(MYST_EXEC) $(OPTS) ext2rootfs /opt/openjdk-13/bin/java --app-config-path config.json --max-affinity-cpus=1

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) ext2rootfs /opt/openjdk-13/bin/java --app-config-path config.json --max-affinity-cpus=1

clean:
	rm -rf ext2rootfs appdir 