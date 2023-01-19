TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=HelloWorld

#ifdef STRACE
#OPTS += --strace
#endif

all: appdir private.pem

run-unsigned:
	$(MYST) mkcpio appdir rootfs
	$(MYST_EXEC) $(OPTS) --memory-size=1024m --thread-stack-size=1m rootfs /app/HelloWorld

_run: appdir private.pem
	timeout 45m $(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME) $(OPTS)

run:
	$(RUNTEST) make -C $(CURDIR) _run

gdb: appdir private.pem
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) -m Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	sudo rm -fr appdir rootfs HelloWorld/build HelloWorld/obj HelloWorld/bin myst private.pem
