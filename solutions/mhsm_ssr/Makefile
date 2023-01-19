TOP=$(abspath ../..)
include $(TOP)/defs.mak
APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=test_ssr
PKEY_FILE=p.pem

all: appdir

appdir:
	g++ -g -o $(APPNAME) test_ssr.c -ldl -I$(TOP)/include
	$(APPBUILDER) -m Dockerfile

$(PKEY_FILE):
	./gen_pkey.sh $(PKEY_FILE)

_run: appdir $(PKEY_FILE)
	$(MYST) package appdir p.pem config.json
	rm -rf $(PKEY_FILE)
	./myst/bin/$(APPNAME)
	
run:
	$(RUNTEST) make -C $(CURDIR) _run

gdb: appdir $(PKEY_FILE)
	$(MYST) package appdir p.pem config.json
	rm -rf $(PKEY_FILE)
	$(MYST_GDB) --args ./myst/bin/$(APPNAME)

clean:
	rm -rf appdir myst *.o $(APPNAME) $(PKEY_FILE)
