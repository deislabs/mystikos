TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
TEST=/aspnetcore/artifacts/bin/Microsoft.AspNetCore.Authentication.Core.Test/Debug/net6.0/Microsoft.AspNetCore.Authentication.Core.Test.dll

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

ifdef MEMCHK
OPTS += --memcheck
endif

# 15 mins
export TIMEOUT=900

OPTS += --app-config-path config.json
# OPTS += --max-affinity-cpus=1

# Set default tests file for runner.
TESTS_FILE=/tests/unit-tests.runner.passed

all: ext2fs

# alpine release build: vtikoo/aspnetcore-build:smaller
# ubuntu debug build: vtikoo/aspnetcore:oct8-2021
appdir:
	$(APPBUILDER) -d Dockerfile.runner

ext2fs: appdir
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs roothash myst /tmp/myst*

tests.old: ext2fs
	$(RUNTEST) ./test-runner.sh

tests: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.1 ""
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.2 ""
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.3 ""
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.4 ""
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.5 ""

one: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST)

one-runner: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TEST)

all-runner: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TESTS_FILE) ""

all-runner-hostfs: appdir
	$(MYST_EXEC) appdir $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TESTS_FILE) ""

#################################
#			dev targets			#
#################################
run-ext2-lldb:
	$(MYST_LLDB) -- $(MYST_EXEC) ext2fs --roothash=roothash \
	$(OPTS) --report-native-tids \
	/aspnetcore/.dotnet/dotnet test $(TEST)

run-hostfs-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) appdir $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST) -v m

ct:
	sudo rm -fr /tmp/myst*
