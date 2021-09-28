TOP=$(abspath ../..)
include $(TOP)/defs.mak
APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=test_ssr

all: appdir

appdir:
	g++ -g -o $(APPNAME) test_ssr.c -ldl
	$(APPBUILDER) Dockerfile

run: appdir
	echo "dump env variables CLIENT_ID etc"
	echo "CLIENT_ID=" $(CLIENT_ID)
	echo "APP_ID=" $(APP_ID)
	echo "SSS=" $(CLIENT_SECRET)
	echo "SSS2=" $(MHSM_CLIENT_SECRET)
	echo "AZURE_CLIENT_ID=" $(AZURE_CLEINT_ID)
	echo "AZURE_TENANT_ID=" $(AZURE_TENANT_ID)
	$(MYST) package appdir private.pem config.json
	./myst/bin/$(APPNAME)

gdb: appdir
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args ./myst/bin/$(APPNAME)

clean:
	rm -rf appdir myst *.o $(APPNAME)
