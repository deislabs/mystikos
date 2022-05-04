TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

all: rootfs

appdir: Dockerfile
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkext2 --force appdir rootfs

OPTS =
OPTS += --thread-stack-size=1m
OPTS += --memory-size=1g

SGX2_PRESENT := $(shell $(BUILDDIR)/openenclave/bin/oesgx | grep -c SGX2)

__run: rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/hello

run:
ifeq ($(SGX2_PRESENT),1)
	make __run
endif

clean:
	rm -rf appdir rootfs
