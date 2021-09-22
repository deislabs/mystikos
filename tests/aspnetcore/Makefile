TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=corerun
HEAP_SIZE="4G"
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

OPTS += --nobrk --app-config-path config.json
# OPTS += --max-affinity-cpus=1

all: appdir rootfs ext2fs

# alpine release build: vtikoo/aspnetcore-build:smaller
# ubuntu debug build: vtikoo/aspnetcore:ubuntu
appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

ext2fs: rootfs
	sudo $(MYST) mkext2 appdir ext2fs
	$(MYST) fssig --roothash ext2fs > roothash

clean:
	sudo rm -fr appdir ext2fs rootfs roothash myst /tmp/myst*

##################################
#			dev targets			 #
##################################
run-ext2:
	$(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) $(OPTS) \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) -v m

run-ext2-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) $(OPTS) --report-native-tids \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) -v diag

run-ext2-gdb2:
	$(MYST_GDB) --args $(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE) $(OPTS) --report-native-tids \
	/aspnetcore/.dotnet/dotnet exec \
	/aspnetcore/.dotnet/sdk/6.0.100-preview.2.21118.6/MSBuild.dll \
	-maxcpucount -verbosity:diag -restore -target:VSTest \
	-nodereuse:false \
	-nologo \
	/aspnetcore/src/Middleware/Session/test/Microsoft.AspNetCore.Session.Tests.csproj

run-ext2-lldb:
	$(MYST_LLDB) -- $(MYST_EXEC) ext2fs --roothash=roothash \
	--memory-size $(HEAP_SIZE)  --report-native-tids \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) $(OPTS)

run-cpio:
	$(MYST_EXEC) rootfs \
	--memory-size $(HEAP_SIZE) --report-native-tids \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) $(OPTS)

run-cpio-gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs \
	--memory-size $(HEAP_SIZE) --report-native-tids \
	/aspnetcore/.dotnet/dotnet test \
	$(TEST) $(OPTS) 

ct:
	sudo rm -fr /tmp/myst*
