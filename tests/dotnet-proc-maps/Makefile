TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=HelloWorld

ifdef STRACE
OPTS += --strace
endif

all: rootfs

tests:
	COMPlus_EnableDiagnostics=0 $(RUNTEST) ./exec.sh $(MYST_EXEC) $(OPTS) --app-config-path config.json rootfs /app/HelloWorld
	@ echo "=== passed test (dotnet-proc-maps)"

gdb: rootfs
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --memory-size=1024m rootfs /app/HelloWorld

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

clean:
	sudo rm -fr appdir rootfs HelloWorld/build HelloWorld/obj HelloWorld/bin
