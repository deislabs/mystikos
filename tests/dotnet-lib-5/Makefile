TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
MYST-RETRY=$(TOP)/scripts/myst-retry
DOCKER_IMAGE_MUSL=hullcritical/dotnet-library-test:release-musl
DOCKER_IMAGE_GLIBC=hullcritical/dotnet-library-test:release-glibc
DOTNET=/dotnet-lib-release/testhost/net5.0-Linux-Release-x64/dotnet
TEST_DLL=

ifdef STRACE
OPTS += --strace
endif

all: build-runner

build: rootfs

appdir:
	$(MYST-RETRY) $(APPBUILDER) -m -i $(DOCKER_IMAGE_MUSL)

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

# Run all tests using custom runner
tests:
	./test_runner.sh $(TARGET) musl custom

# Run a test given a DLL in Mystikos
run-single:
	$(MYST_EXEC) $(OPTS) rootfs --app-config-path config.json $(DOTNET) test $(TEST_DLL)

clean:
	rm -rf appdir rootfs appdirr rootfsr

# Run test with Docker

# Run a single test DLL in docker
run-docker:
	docker run $(DOCKER_IMAGE_GLIBC) $(DOTNET) test $(TEST_DLL)

# Run test with Runner

RUNNER=/runner/bin/Release/net5.0/runner
RROOTFS=rootfsr
RAPPDIR=appdirr

build-runner: $(RROOTFS)

rootfsr: $(RAPPDIR)
	$(MYST) mkext2 $(RAPPDIR) $(RROOTFS)

appdirr:
	$(MYST-RETRY) $(APPBUILDER) -m -o $(RAPPDIR) Dockerfile.musl.runner 

TESTCASE=testcases/pass.txt

run-runner:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(RROOTFS) --app-config-path config-runner.json $(RUNNER) /testcases/pass.1 /dotnet-lib-release/
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(RROOTFS) --app-config-path config-runner.json $(RUNNER) /testcases/pass.2 /dotnet-lib-release/
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(RROOTFS) --app-config-path config-runner.json $(RUNNER) /testcases/pass.3 /dotnet-lib-release/
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(RROOTFS) --app-config-path config-runner.json $(RUNNER) /testcases/pass.4 /dotnet-lib-release/

gdb-runner:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) $(RROOTFS) --app-config-path config-runner.json $(RUNNER) /$(TESTCASE) /dotnet-lib-release/
