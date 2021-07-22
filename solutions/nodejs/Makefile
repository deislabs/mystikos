TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

OPTS += --memory-size=1024m

all: rootfs

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

TIMEOUT=60s

run:
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/node /app/app.js & echo $$! > server.pid
	./wait.sh
	curl 127.0.0.1:3000 >> client.output
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	grep -q "Hello World" client.output

clean:
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	rm -rf rootfs appdir server.pid client.output
