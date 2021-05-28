TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=webapp

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=1024m

all: appdir private.pem

TIMEOUT=120s

run: appdir private.pem
	# Kill the server from a previous run if it wasn't shut down properly.
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME) $(OPTS) > server.output & echo $$! > server.pid
	timeout $(TIMEOUT) tail -f server.output | ./client.sh
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	test -f client.output

# run the server in the foreground:
server:
	$(MAKE) appdir
	$(MAKE) rootfs
	$(MYST_EXEC) rootfs /app/webapp $(OPTS)

# run the client
client:
	curl 127.0.0.1:5050

rootfs:
	sudo $(MYST) mkext2 appdir rootfs
	sudo chown $(USER).$(USER) rootfs
	truncate --size=-4096 rootfs

gdb: appdir private.pem
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) Dockerfile

rootfs:
	sudo $(MYST) mkext2 appdir rootfs
	sudo chown $(USER).$(USER) rootfs
	truncate --size=-4096 rootfs

# standalone server rule:
server:
	$(MAKE) appdir
	$(MAKE) rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/webapp

# standalone client rule:
client:
	curl 127.0.0.1:5050

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	sudo rm -fr appdir rootfs build obj bin myst private.pem server.pid server.output client.output
