TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
HEAP_SIZE="768M"
TEST_FILE=pr0-tests-all
TEST_CASE=JIT/Generics/Arrays/TypeParameters/Jagged/class01/class01.dll

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size $(HEAP_SIZE)

all: rootfs ext2fs

# docker build time ~1hr. Using prebuilt image.
# Other docker images:
# pr1(~10k tests) tests in debug
#$(APPBUILDER) vtikoo/coreclr-tests:release
# runtime with debug symbols -
#$(APPBUILDER) vtikoo/coreclr-tests:debug3
appdir:
	# pr0(~2.7k tests) tests in release
	$(APPBUILDER) -i vtikoo/coreclr-tests:pr0-release

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

run:
	./test-runner.sh $(MYST_EXEC) ext2 $(TEST_FILE)

clean:
	sudo rm -fr appdir ext2fs rootfs roothash myst /tmp/myst* PASSED FAILED-*

##################################
#			dev targets			 #
##################################

run-ext2:
	COMPlus_EnableDiagnostics=0 $(MYST_EXEC) ext2fs \
	--roothash=roothash $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

run-ext2-gdb:
	COMPlus_EnableDiagnostics=0 $(MYST_GDB) \
	--args $(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

ct:
	sudo rm -fr /tmp/myst* PASSED FAILED-*
