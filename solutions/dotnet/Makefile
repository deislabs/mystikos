TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=HelloWorld

OPTS =

ifdef STRACE
OPTS += --strace
endif

#OPTS += --perf

all: rootfs private.pem

export MYST_ROOTFS_PATH=$(CURDIR)/rootfs

rootfs: appdir
	$(MYST) mkext2 appdir rootfs
	$(MYST) fssig --roothash rootfs > roothash

run: all
	timeout 45m $(MYST) package --roothash=roothash private.pem config.json
	myst/bin/$(APPNAME) $(OPTS)

gdb: all
	$(MYST) package --roothash=roothash private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	sudo rm -rf appdir rootfs HelloWorld/build HelloWorld/obj HelloWorld/bin myst private.pem
