TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=webapp

ifdef STRACE
OPTS += --strace
endif

OPTS = --memory-size=1024m

all: appdir private.pem

run: appdir private.pem
	# Kill the server from a previous run if it wasn't shut down properly.
	test -f server.pid && kill -9 `cat server.pid` || true
	$(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME) $(OPTS) & echo $$! > server.pid
	sleep 60
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

rootfs:
	sudo $(MYST) mkext2 appdir rootfs
	sudo chown $(USER).$(USER) rootfs
	truncate --size=-4096 rootfs

export COMPlus_EnableDiagnostics=0
export COMPlus_GCHeapHardLimit=0x08000000

# standalone server rule:
server:
	$(MAKE) appdir
	$(MAKE) rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/webapp

# standalone client rule:
client:
	time curl 127.0.0.1:5050

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	sudo rm -fr appdir rootfs build obj bin myst private.pem server.pid
