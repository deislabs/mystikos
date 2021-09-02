TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=webapp

ifdef STRACE
OPTS += --strace
endif

ifdef PERF
OPTS += --perf
endif

OPTS += --memory-size=1024m

# ATTN: this setting causes curl to get empty responses after two attempts
#OPTS += --max-affinity-cpus=1

all: appdir private.pem

TIMEOUT=300s

export COMPlus_EnableDiagnostics=0
export COMPlus_GCHeapHardLimit=0x8000000

run: rootfs private.pem
	./kill.sh
	timeout $(TIMEOUT) $(MYST_EXEC) $(OPTS) rootfs /app/webapp &
	timeout $(TIMEOUT) ./wait.sh
	./client.sh
	./kill.sh
	test -f client.output

# run the server in the foreground:
server: rootfs
	$(MYST_EXEC) rootfs /app/webapp $(OPTS)

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

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	./kill.sh
	sudo rm -fr appdir rootfs build obj bin myst private.pem client.output
