TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun

ifdef STRACE
OPTS += --strace
endif

all: appdir private.pem myst

run:
	myst/bin/$(APPNAME) /coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)
	cleantmp
	
gdb:
	$(MYST_GDB) --args myst/bin/$(APPNAME) /coreclr-tests-all/GC/Scenarios/MinLeakGen/minleakgen/minleakgen.dll $(OPTS)

# docker build time ~1hr. Using prebuilt image.
appdir:
	# pr0(~2.7k tests) tests in release
	$(APPBUILDER) vtikoo/coreclr-tests:pr0-release
	# pr1(~10k tests) tests in debug
	#$(APPBUILDER) vtikoo/coreclr-tests:release
	# runtime with debug symbols -
	#$(APPBUILDER) vtikoo/coreclr-tests:debug3

rootfs:
	$(MYST) mkcpio appdir rootfs

myst:
	$(MYST) package appdir private.pem config.json

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -fr appdir rootfs private.pem myst /tmp/myst*

cleantmp:
	rm -fr /tmp/myst*