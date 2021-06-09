TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=python3

ifdef STRACE
OPTS = --strace
endif

all: myst/bin/$(APPNAME)

appdir:
	$(APPBUILDER) Dockerfile

myst/bin/$(APPNAME): appdir private.pem
	$(MYST) package appdir private.pem config.json

run: myst/bin/$(APPNAME)
	myst/bin/$(APPNAME) $(OPTS)

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs appdir myst private.pem
