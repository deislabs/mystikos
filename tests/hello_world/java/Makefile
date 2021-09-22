TOP = $(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
	OPTS = --strace
endif

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkext2 --force appdir ext2rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2rootfs /opt/openjdk-13/bin/java -ea Helloworld red green blue --app-config-path config.json --max-affinity-cpus=1

clean:
	rm -rf ext2rootfs appdir

