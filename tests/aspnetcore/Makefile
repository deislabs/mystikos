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

all: ext2fs

# alpine release build: vtikoo/aspnetcore-build:smaller
# ubuntu debug build: vtikoo/aspnetcore:oct8-2021
appdir:
	$(APPBUILDER) -i mystikos/aspnetcore:slim

ext2fs: appdir
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs roothash myst /tmp/myst*

tests:
	$(RUNTEST) ./test-runner.sh
one:
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST)

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
