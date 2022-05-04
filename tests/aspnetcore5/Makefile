TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

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

OPTS += --app-config-path config.json

all: ext2fs

appdir:
	$(MYST-RETRY) docker pull mcr.microsoft.com/dotnet/sdk:5.0-focal
	$(APPBUILDER) -m -d Dockerfile.runner

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs
	# $(MYST) fssig --roothash ext2fs > roothash

clean:
	rm -fr appdir ext2fs roothash

tests: ext2fs
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.1 ""
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.2 ""
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.3 ""
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.4 ""
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.5 ""

ID=1
test-single: ext2fs
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.$(ID) ""

test-single-lldb:
	$(MYST_LLDB) -- $(MYST_EXEC) ext2fs $(OPTS) \
	--report-native-tids \
	/runner/bin/Debug/net5.0/runner /tests/unit-tests.runner.$(ID) "/"

one: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST)

run-runner:
	$(MYST_EXEC) ext2fs $(OPTS) \
	/runner/bin/Debug/net5.0/runner $(ARG1) $(ARG2)

run-runner-lldb:
	$(MYST_LLDB) -- $(MYST_EXEC) ext2fs $(OPTS) \
	--report-native-tids \
	/runner/bin/Debug/net5.0/runner $(ARG1) $(ARG2)

all-runner: ext2fs
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/runner/bin/Debug/net6.0/runner $(TESTS_FILE) ""
