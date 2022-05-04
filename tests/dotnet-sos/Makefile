TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
MYST-RETRY=$(TOP)/scripts/myst-retry
HEAP_SIZE="768M"

MYST_LLDB_DOCKER = /build/openenclave/bin/oelldb
TEST_RUNNER_IMG = mystikos/dotnet-sos-prereqs:jan-18-2022

OPTS = --report-native-tids

ifdef STRACE
OPTS += --strace
endif

all: ext2fs runner-image

appdir:
	$(MYST-RETRY) docker pull mcr.microsoft.com/dotnet/sdk:6.0
	$(MYST-RETRY) docker pull mcr.microsoft.com/dotnet/runtime:6.0
	$(APPBUILDER) -m Dockerfile
	# libmscordaccore is required by sos_test.py
	cp appdir/app/libmscordaccore.so .

ext2fs: appdir
	rm -rf appdir/tmp/clr-debug-pipe*
	$(MYST) mkext2 appdir ext2fs

runner-image:
	docker pull $(TEST_RUNNER_IMG)

clean:
	sudo rm -fr appdir ext2fs rootfs stdouterr.txt libmscordaccore.so

DOCKER_SGX_DRIVER_OPTIONS = -v /dev/sgx:/dev/sgx
DOCKER_SGX_DRIVER_OPTIONS += --device /dev/sgx/enclave:/dev/sgx/enclave
DOCKER_SGX_DRIVER_OPTIONS += --device /dev/sgx/provision:/dev/sgx/provision
DOCKER_SGX_DRIVER_OPTIONS += --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket
DOCKER_SGX_DRIVER_OPTIONS += --env SGX_AESM_ADDR=1
tests:
	SUBTEST=dotnet-sos $(RUNTEST) docker run --rm -e TARGET=$(TARGET) -v $(abspath .):/app/ -v $(TOP)/build:/build $(DOCKER_SGX_DRIVER_OPTIONS) $(TEST_RUNNER_IMG) /app/exec.sh $(MYST_LLDB_DOCKER) /build/bin/myst $(EXEC) $(OPTS)
	@ echo "=== passed test (dotnet-sos)"

tests-without-docker:
	$(RUNTEST) ./exec.sh $(MYST_LLDB) $(MYST) $(EXEC) $(OPTS)

##################################
#			dev targets			 #
##################################
run-ext2:
	$(MYST_EXEC) ext2fs \
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

t:
	echo ${DEV_SGX_ISDIR}

prereqs:
	@docker build -f Dockerfile-prereqs .
