TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="768M"

MYST_LLDB_DOCKER = /build/openenclave/bin/oelldb
TEST_RUNNER_IMG = mystikos/dotnet-sos-prereqs:20200805

OPTS = --report-native-tids

ifdef STRACE
OPTS += --strace
endif

all: ext2fs runner-image

appdir:
	$(APPBUILDER) Dockerfile
	$(SQUASH-APPDIR) appdir

ext2fs: appdir
	rm -rf appdir/tmp/clr-debug-pipe*
	$(MYST) mkext2 appdir ext2fs

runner-image:
	docker pull $(TEST_RUNNER_IMG)

clean:
	sudo rm -fr appdir ext2fs rootfs stdouterr.txt

tests:
	$(RUNTEST) docker run --rm \
	-e TARGET=$(TARGET) \
	-v $(abspath .):/app/ -v $(TOP)/build:/build \
	--device /dev/sgx:/dev/sgx \
	$(TEST_RUNNER_IMG) \
	/app/exec.sh $(MYST_LLDB_DOCKER) /build/bin/myst $(EXEC) $(OPTS)
	@ echo "=== passed test (dotnet-sos)"

tests-without-docker:
	$(RUNTEST) ./exec.sh $(MYST_LLDB) $(MYST) $(EXEC) $(OPTS)

##################################
#			dev targets			 #
##################################
run-ext2:
	$(MYST) exec ext2fs \
	--memory-size $(HEAP_SIZE) \
	/app/hello

run-ext2-lldb:
	DOTNET_SOURCE_DIRS=$(abspath .)/hello $(MYST_LLDB) -o "command script import ignore_sigill" \
	-o "command script import code_view" \
	-o "bpmd hello.dll hello.Program.Main" \
	-o "setsymbolserver -directory $(abspath .)/appdir/app" \
	-- $(MYST_EXEC) $(OPTS) ext2fs \
	--memory-size $(HEAP_SIZE) \
	/app/hello

ct:
	sudo rm -fr /tmp/myst*
