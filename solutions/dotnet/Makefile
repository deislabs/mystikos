TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=HelloWorld

#ifdef STRACE
#OPTS += --strace
#endif

all: appdir private.pem

# This will crash due to insufficient heap memory for dotnet runtime.
# Default is 64mb, and the runtime requires at least 512mb.
# Enable after issue 146 is resolved.
#run-unsigned:
#	$(MYST) mkcpio appdir rootfs
#	$(MYST_EXEC) $(OPTS) rootfs /HelloWorld/build/HelloWorld

run: appdir private.pem
	$(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME) $(OPTS)
	
gdb: appdir private.pem
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	$(APPBUILDER) Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	sudo rm -fr appdir rootfs HelloWorld/build HelloWorld/obj HelloWorld/bin myst private.pem
