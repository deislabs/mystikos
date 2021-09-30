TOP=$(abspath ../..)
include $(TOP)/defs.mak
APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=test_ssr

all: appdir

appdir:
	g++ -g -o $(APPNAME) test_ssr.c -ldl
	$(APPBUILDER) Dockerfile

run: appdir
	echo "$(SSR_PRIVATE_KEY)" > private.pem
	$(MYST) package appdir private.pem config.json
	rm private.pem
	./myst/bin/$(APPNAME)

gdb: appdir
	$(MYST) package appdir private.pem config.json
	$(MYST_GDB) --args ./myst/bin/$(APPNAME)

clean:
	rm -rf appdir myst *.o $(APPNAME)
