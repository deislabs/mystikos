TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
TEST=/aspnetcore/artifacts/bin/Microsoft.AspNetCore.Authentication.Core.Test/Debug/net6.0/Microsoft.AspNetCore.Authentication.Core.Test.dll

MYST-RETRY=$(TOP)/scripts/myst-retry

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

ifdef MEMCHK
OPTS += --memcheck
endif

ifdef STRACE_FAILING
OPTS += --strace-failing
endif

ifdef STRACE_FILTER
OPTS += --strace-filter=$(STRACE_FILTER)
endif

ifdef FILTER
FILTER_OPT = --filter $(FILTER)
endif

# 15 mins
export TIMEOUT=900

OPTS += --app-config-path config.json
# OPTS += --max-affinity-cpus=1

# Set default tests file for runner.
TESTS_FILE=/tests/unit-tests.runner.1

all: ext2fs

# alpine release build: vtikoo/aspnetcore-build:smaller
# ubuntu debug build: vtikoo/aspnetcore:oct8-2021
appdir:
	$(MYST-RETRY) docker pull mcr.microsoft.com/dotnet/sdk:6.0
	$(APPBUILDER) -m -d Dockerfile.runner

ext2fs: appdir
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs roothash myst /tmp/myst*

tests.old: ext2fs
	$(RUNTEST) ./test-runner.sh

tests: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.1 "" $(FILTER_OPT)
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.2 "" $(FILTER_OPT)
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.3 "" $(FILTER_OPT)
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.4 "" $(FILTER_OPT)
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner /tests/unit-tests.runner.5 "" $(FILTER_OPT)

one: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST)  $(FILTER_OPT)

one-runner: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TEST)  $(FILTER_OPT)

one-runner-hostfs: appdir
	$(MYST_EXEC) appdir $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TEST)  $(FILTER_OPT)

all-runner: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TESTS_FILE) "" $(FILTER_OPT)

all-runner-hostfs: appdir
	$(MYST_EXEC) appdir $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TESTS_FILE) "" $(FILTER_OPT)

#################################
#			dev targets			#
#################################
run-ext2-lldb:
	$(MYST_LLDB) -- $(MYST_EXEC) ext2fs --roothash=roothash \
	$(OPTS) --report-native-tids \
	/runner/bin/Debug/net6.0/runner $(TEST)  $(FILTER_OPT)

run-hostfs-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) appdir $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST) -v m

ct:
	sudo rm -fr /tmp/myst*
