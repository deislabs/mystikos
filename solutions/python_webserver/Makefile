TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

OPTS =

ifdef STRACE
OPTS += --strace
endif

ifdef TTRACE
OPTS += --ttrace
endif

OPTS += --memory-size=1024m

all: rootfs

USE_ROOTHASH=1

rootfs: appdir
	sudo $(MYST) mkext2 appdir rootfs
ifdef USE_ROOTHASH
	$(MYST) fssig --roothash rootfs > roothash
else
	truncate --size=-4096 rootfs
endif

ifdef USE_ROOTHASH
OPTS += --roothash=roothash
endif

appdir:
	$(APPBUILDER) Dockerfile

TIMEOUT=60s

run:
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST_EXEC) $(OPTS) rootfs /miniconda/bin/python3 /app/hello_server.py > server.output & echo $$! > server.pid
	timeout $(TIMEOUT) tail -f server.output | ./client.sh
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	test -f client.output

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf rootfs appdir server.output server.pid client.output
