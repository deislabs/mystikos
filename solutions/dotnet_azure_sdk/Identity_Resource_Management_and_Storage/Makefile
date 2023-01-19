TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=AzureIdentityStorageExample
SRC = src/*.csproj src/*.cs

all: appdir private.pem

run: appdir private.pem
	$(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME)

gdb: appdir private.pem
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args myst/bin/$(APPNAME)

appdir: $(SRC)
	$(MAKE) clean
	$(APPBUILDER) -m Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	sudo rm -rf appdir rootfs build obj bin myst private.pem
