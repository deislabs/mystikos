TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=HelloWorld

ifdef STRACE
OPTS += --strace
endif

all: rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) --memory-size=1024m rootfs /app/HelloWorld > actual.txt
	@cat actual.txt | grep -E "HelloWorld" > /dev/null
	@ echo "=== passed test (dotnet-proc-maps)"
	
gdb: rootfs
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --memory-size=1024m rootfs /app/HelloWorld

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

clean:
	sudo rm -fr appdir rootfs HelloWorld/build HelloWorld/obj HelloWorld/bin actual.txt
