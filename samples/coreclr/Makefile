TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun

ifdef STRACE
OPTS += --strace
endif

all: appdir private.pem libos

run:
	libos/bin/$(APPNAME) /coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)
	
gdb:
	$(LIBOS_GDB) --args libos/bin/$(APPNAME) /coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

# docker build time ~1hr. Using prebuilt image.
appdir:
	$(APPBUILDER) vtikoo/coreclr-tests:release
	# For dotnet runtime with debug symbols choose -
	#$(APPBUILDER) vtikoo/coreclr-tests:debug3

rootfs:
	$(LIBOS) mkcpio appdir rootfs

libos:
	$(LIBOS) package appdir private.pem config.json

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -fr appdir rootfs private.pem libos /tmp/libos*