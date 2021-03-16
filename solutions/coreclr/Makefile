TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
HEAP_SIZE="768M"

ifdef STRACE
OPTS += --strace
endif

OPTS = --memory-size=256m

all: appdir rootfs ext2fs

# docker build time ~1hr. Using prebuilt image.
# Other docker images:
# pr1(~10k tests) tests in debug
#$(APPBUILDER) vtikoo/coreclr-tests:release
# runtime with debug symbols -
#$(APPBUILDER) vtikoo/coreclr-tests:debug3
appdir:
	# pr0(~2.7k tests) tests in release
	$(APPBUILDER) vtikoo/coreclr-tests:pr0-release

rootfs:
	$(MYST) mkcpio appdir rootfs

ext2fs:
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

run:
	./test-runner.sh $(MYST_EXEC) ext2 pr0-tests-all

clean:
	sudo rm -fr appdir ext2fs rootfs roothash myst /tmp/myst* PASSED FAILED-*

##################################
#			dev targets			 #
##################################
run-cpio:
	$(MYST) exec rootfs \
	--memory-size $(HEAP_SIZE) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

run-cpio-gdb:
	$(MYST_GDB) --args $(MYST) exec rootfs \
	--memory-size $(HEAP_SIZE) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

run-ext2:
	$(MYST) exec ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST) exec ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll $(OPTS)

ct:
	sudo rm -fr /tmp/myst* PASSED FAILED-*
