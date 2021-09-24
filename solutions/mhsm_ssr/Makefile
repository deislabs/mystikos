TOP=$(abspath ../..)
include $(TOP)/defs.mak
APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=test_ssr

all: appdir

appdir:
	echo $CLIENT_ID
	echo $APP_ID
	echo $AZURE_CLEINT_ID
	echo $AZURE_TENANT_ID
	g++ -g -o $(APPNAME) test_ssr.c -ldl
	$(APPBUILDER) Dockerfile

run: appdir
	$(MYST) package appdir private.pem config.json
	./myst/bin/$(APPNAME)

gdb: appdir
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args ./myst/bin/$(APPNAME)

clean:
	rm -rf appdir myst *.o $(APPNAME)
