TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

OPTS = --memory-size=128m

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	$(MYST) mkcpio appdir rootfs

run:
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/hello_server.py & echo $$! > server.pid
	sleep 20
	curl 127.0.0.1:8000
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf rootfs appdir server.pid
