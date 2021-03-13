TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=webapp

#ifdef STRACE
#OPTS += --strace
#endif

OPTS = --user-mem-size=256m

all: appdir private.pem

run: appdir private.pem
	# Kill the server from a previous run if it wasn't shut down properly.
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME) $(OPTS) & echo $$! > server.pid
	sleep 10
	# Request 3 times from the client to make sure the server is robust.
	curl 127.0.0.1:5050
	curl 127.0.0.1:5050
	curl 127.0.0.1:5050
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	
gdb: appdir private.pem
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	sudo rm -fr appdir rootfs build obj bin myst private.pem server.pid
