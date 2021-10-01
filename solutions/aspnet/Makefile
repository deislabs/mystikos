TOP=$(abspath ../..)
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

# ATTN: this setting causes curl to get empty responses after two attempts
#OPTS += --max-affinity-cpus=1

all: appdir private.pem

TIMEOUT=30s

export COMPlus_EnableDiagnostics=0
export COMPlus_GCHeapHardLimit=0x10000000

run: rootfs private.pem
	./kill.sh
	timeout $(TIMEOUT) $(MYST_EXEC) $(OPTS) rootfs /app/webapp &
	timeout $(TIMEOUT) ./wait.sh
	./client.sh
	./kill.sh
	test -f client.output

# run the server in the foreground:
server: rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/webapp 

# run the client
client:
	curl 127.0.0.1:5050

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

gdb: appdir private.pem
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) Dockerfile
	$(SQUASH-APPDIR) appdir

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	./kill.sh
	sudo rm -fr appdir rootfs build obj bin myst private.pem client.output
