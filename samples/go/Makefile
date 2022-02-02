TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

all: rootfs

rootfs: appdir
	$(MYST) mkext2 --force appdir rootfs

appdir:
	rm -rf appdir
	$(APPBUILDER) Dockerfile

OPTS =
OPTS += --thread-stack-size=1m
OPTS += --memory-size=1g

run: rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/hello

clean:
	rm -rf appdir rootfs
