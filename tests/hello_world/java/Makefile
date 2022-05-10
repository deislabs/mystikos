TOP = $(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

OPTS = --app-config-path config.json

ifdef STRACE
	OPTS += --strace
endif

all: appdir rootfs

appdir:
	$(APPBUILDER) -m -p Dockerfile

rootfs: appdir
	$(MYST) mkext2 --force appdir ext2rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2rootfs /opt/openjdk-13/bin/java -ea Helloworld red green blue 

clean:
	rm -rf ext2rootfs appdir

