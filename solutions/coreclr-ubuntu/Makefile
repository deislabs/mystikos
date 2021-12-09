TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
TEST_CASE=GC/Scenarios/ServerModel/servermodel/servermodel.dll
PACKAGE_PATH  = myst/bin/corerun

ifdef STRACE
OPTS += --strace
endif
OPTS += --app-config-path=config_3g.json

all: ext2fs build-package

appdir:
	$(APPBUILDER) -i vtikoo/coreclr-tests:5-ubuntu-release-p0

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

build-package: package.pem
	$(MYST) fssig --roothash ext2fs > roothash
	$(MYST) package-sgx --roothash=roothash package.pem config_256m.json

run:
	./test-runner.sh $(PACKAGE_PATH) null null 30 package pr0-256m
	./test-runner.sh $(MYST_EXEC) config_1g.json 30 ext2 pr0-1g
	./test-runner.sh $(MYST_EXEC) config_1.8g.json 30 ext2 pr0-1.8g
	./test-runner.sh $(MYST_EXEC) config_1g.json 180 ext2 pr0-long
	./test-runner.sh $(MYST_EXEC) config_1g.json 360 ext2 pr0-long++
	./test-runner.sh $(MYST_EXEC) config_3g.json 480 ext2 pr0-3g-long++
	./stat.sh

package.pem:
	openssl genrsa -out package.pem -3 3072

clean:
	sudo rm -fr appdir ext2fs roothash myst /tmp/myst* PASSED FAILED-* package.pem

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -s all
	@ $(MAKE) -s run

##################################
#			dev targets			 #
##################################

run-ext2:
	$(MYST_EXEC) ext2fs \
	$(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs $(OPTS) \
	/coreclr-tests-all/Tests/Core_Root/corerun \
	/coreclr-tests-all/$(TEST_CASE)

ct:
	sudo rm -fr /tmp/myst* PASSED FAILED-*
