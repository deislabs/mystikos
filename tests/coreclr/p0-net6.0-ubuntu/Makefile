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

all: ext2fs

# docker build time ~1hr. Using prebuilt image.
appdir:
	# pr0(~2.8k tests) tests in release
	$(APPBUILDER) -i jxyang100/coreclr-tests:pr0-release

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

run:
	rm -rf PASSED FAILED-*
ifndef MYST_SKIP_PR_TEST
	$(TEST_RUNNER) $(MYST_EXEC) config_1g.json 60 ext2 pr0-1g
	$(TEST_RUNNER) $(MYST_EXEC) config_4g.json 60 ext2 pr0-large-memory
	$(TEST_RUNNER) $(MYST_EXEC) config_1g.json 300 ext2 pr0-long-time
endif
	$(STAT) pr0-tests-all 95

clean:
	sudo rm -fr appdir ext2fs roothash PASSED FAILED-*

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
