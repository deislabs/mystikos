TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
TEST=/aspnetcore/src/Middleware/Session/test/Microsoft.AspNetCore.Session.Tests.csproj

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

ifdef MEMCHK
OPTS += --memcheck
endif

OPTS += --memory-size 2G --nobrk --app-config-path config.json
# OPTS += --max-affinity-cpus=1

all: appdir ext2fs

# alpine release build: vtikoo/aspnetcore-build:smaller
# ubuntu debug build: vtikoo/aspnetcore:ubuntu
appdir:
	$(APPBUILDER) Dockerfile

ext2fs:
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs roothash myst /tmp/myst*

tests:
	$(RUNTEST) ./test-runner.sh
one:
	$(MYST_EXEC) ext2fs --roothash=roothash $(OPTS) \
	/aspnetcore/.dotnet/dotnet test $(TEST)

##################################
#			dev targets			 #
##################################
run-ext2:
	$(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) $(OPTS) \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) -v m

run-ext2-lldb:
	$(MYST_LLDB) -- $(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE)  --report-native-tids \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) $(OPTS)

run-hostfs-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) appdir \
	--memory-size $(HEAP_SIZE) $(OPTS) \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) -v m

ct:
	sudo rm -fr /tmp/myst*
