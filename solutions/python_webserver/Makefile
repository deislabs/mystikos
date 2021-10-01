TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

OPTS =

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=256m

ifdef PERF
OPTS += --perf
endif

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
	$(SQUASH-APPDIR) appdir

TIMEOUT=60s

run:
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST_EXEC) $(OPTS) rootfs /miniconda/bin/python3 /app/hello_server.py & echo $$! > server.pid
	./wait.sh
	curl 127.0.0.1:8000
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf rootfs appdir server.output server.pid client.output
