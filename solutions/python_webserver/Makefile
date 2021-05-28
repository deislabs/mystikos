TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

OPTS = --memory-size=512m

all: rootfs

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

TIMEOUT=60s

run:
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python3 /app/hello_server.py > server.output & echo $$! > server.pid
	timeout $(TIMEOUT) tail -f server.output | ./client.sh
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	test -f client.output

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf rootfs appdir server.output server.pid client.output
