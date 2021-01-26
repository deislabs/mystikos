TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun

ifdef STRACE
OPTS += --strace
endif

all: appdir rootfs ext2fs

run:
	myst/bin/$(APPNAME) /coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)
	cleantmp
	
gdb:
	$(MYST_GDB) --args myst/bin/$(APPNAME) /coreclr-tests-all/GC/Scenarios/MinLeakGen/minleakgen/minleakgen.dll $(OPTS)

# docker build time ~1hr. Using prebuilt image.
# Other docker images:
# pr1(~10k tests) tests in debug
#$(APPBUILDER) vtikoo/coreclr-tests:release
# runtime with debug symbols -
#$(APPBUILDER) vtikoo/coreclr-tests:debug3
appdir:
	# pr0(~2.7k tests) tests in release
	$(APPBUILDER) vtikoo/coreclr-tests:release

rootfs:
	$(MYST) mkcpio appdir rootfs

ext2fs:
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

run-cpio:
	$(MYST) exec rootfs \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

run-cpio-gdb:
	$(MYST_GDB) --args $(MYST) exec rootfs \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

run-ext2:
	$(MYST) exec ext2fs --roothash=roothash \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST) exec ext2fs --roothash=roothash \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)


clean:
	sudo rm -fr appdir ext2fs rootfs myst /tmp/myst*

ct:
	sudo rm -fr /tmp/myst*