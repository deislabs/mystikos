TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
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
	./test-runner.sh $(MYST_EXEC) config_1g.json 60 pr0-1g
	./test-runner.sh $(MYST_EXEC) config_4g.json 60 pr0-large-memory
	./test-runner.sh $(MYST_EXEC) config_1g.json 300 pr0-long-time
endif
	./stat.sh

clean:
	sudo rm -fr appdir ext2fs roothash myst /tmp/myst* PASSED FAILED-*

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
