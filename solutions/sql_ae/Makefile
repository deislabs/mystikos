.NOTPARALLEL:
.PHONY: all app

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS = --strace
endif

OPTS += --app-config-path config.json

all: myst app
	$(MYST) mkcpio $(APPDIR) rootfs

run: appdir
	$(RUNTEST) $(MYST_EXEC) rootfs /odbc_app classic default $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

app:
	rm -rf app/odbc_app $(APPDIR)
	docker build -t alpine.build -f app-dockerfile .
	docker run --rm -v $(CURDIR)/app:/app alpine.build bash -c "gcc -g -fshort-wchar -fPIC -o /app/cksp.so -shared /app/cksp.c -I/opt/microsoft/msodbcsql17/include; gcc -g -o /app/odbc_app -fshort-wchar /app/odbc_app.c /app/odbc_helper.c -lodbc -ldl -I/opt/microsoft/msodbcsql17/include"
	sudo chown $(USER):$(GROUP) app/odbc_app
	$(TOP)/scripts/appbuilder Dockerfile
	cp app/odbc_app $(APPDIR)/odbc_app
	cp app/cksp.so $(APPDIR)/cksp.so
	# make sure the app we are running is the one we just built.
	ls -l $(APPDIR)/odbc_app $(APPDIR)/cksp.so; date

run-host:
	gcc -g -fshort-wchar -fPIC -o cksp.so -shared app/cksp.c -I/opt/microsoft/msodbcsql17/include
	gcc -g -o odbc_app -fshort-wchar app/odbc_app.c app/odbc_helper.c -lodbc -ldl -I/opt/microsoft/msodbcsql17/include
	./odbc_app msi default

clean:
	rm -rf rootfs $(APPDIR)
	rm -rf app/odbc_app app/cksp.so app/msodbcinstall odbc_app cksp.so
