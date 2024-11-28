TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
CORECLR_COMMON=$(TOP)/tests/coreclr/
TEST_RUNNER=$(CORECLR_COMMON)/test-runner.sh
RUN_SINGLE_TEST=$(CORECLR_COMMON)/run-single-test.sh
STAT=$(CORECLR_COMMON)/stat.sh

TEST=GC/Scenarios/ServerModel/servermodel/servermodel.dll
PACKAGE_PATH  = myst/bin/corerun

ifdef STRACE
OPTS += --strace
endif
OPTS += --app-config-path=config_1g.json

all: ext2fs build-package

# docker build time ~1hr. Using prebuilt image.
appdir:
	# pr0(~2.8k tests) tests in release
	$(APPBUILDER) -m -i openenclave.azurecr.io/coreclr-tests:pr0-release

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

package.pem:
	openssl genrsa -out package.pem -3 3072

build-package: package.pem
	$(MYST) fssig --roothash ext2fs > roothash
	$(MYST) package-sgx --roothash=roothash package.pem config_256m.json

run:
	rm -rf PASSED FAILED-*
ifndef MYST_SKIP_PR_TEST
	$(TEST_RUNNER) $(PACKAGE_PATH) null null 30 package pr0-256m
	$(TEST_RUNNER) $(MYST_EXEC) config_1g.json 60 ext2 pr0-1g
	$(TEST_RUNNER) $(MYST_EXEC) config_4g.json 40 ext2 pr0-large-memory 1
	$(TEST_RUNNER) $(MYST_EXEC) config_1g.json 300 ext2 pr0-long-time
endif
	$(STAT) pr0-tests-all 97

clean:
	sudo rm -fr appdir ext2fs roothash myst package.pem PASSED FAILED-*

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -s all
	@ $(MAKE) -s run

##################################
#			dev targets			 #
##################################

one:
	$(MYST_EXEC) ext2fs \
	$(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST)

one-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST)

one-package:
	$(PACKAGE_PATH) /coreclr-tests-all/$(TEST) --rootfs=ext2fs
