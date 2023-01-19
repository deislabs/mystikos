TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=webapp

OPTS = --app-config-path config.json

ifdef STRACE
OPTS += --strace
endif

ifdef PERF
OPTS += --perf
endif

all: rootfs

TIMEOUT=30s

_run: rootfs
	./kill.sh
	timeout $(TIMEOUT) $(MYST_EXEC) $(OPTS) rootfs /app/webapp &
	timeout $(TIMEOUT) ./wait.sh
	./client.sh
	./kill.sh
	test -f client.output

run:
	$(RUNTEST) make -C $(CURDIR) _run

# run the server in the foreground:
server: rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/webapp 

# run the client
client:
	curl 127.0.0.1:5050/hello

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

gdb: appdir private.pem
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) -m Dockerfile

clean:
	./kill.sh
	sudo rm -fr appdir rootfs build obj bin myst private.pem client.output
