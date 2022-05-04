TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=python3

ifdef STRACE
OPTS = --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

run: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /miniconda/bin/python3 /app/app.py

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs appdir myst private.pem
