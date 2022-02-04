TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
RUNNER=/runner/bin/Release/net6.0/runner
ROOTFS=rootfs
APPDIR=appdir

ifdef STRACE
OPTS += --strace
endif

all: build

clean:
	rm -rf appdir rootfs

build: $(ROOTFS)

rootfs: $(APPDIR)
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

appdir:
	$(APPBUILDER) -o $(APPDIR) Dockerfile.glibc.runner 

tests:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) --app-config-path config.json $(RUNNER) /testcases/pass.1 /dotnet-lib-release/
	$(MYST_EXEC) $(OPTS) $(ROOTFS) --app-config-path config.json $(RUNNER) /testcases/pass.2 /dotnet-lib-release/
	$(MYST_EXEC) $(OPTS) $(ROOTFS) --app-config-path config.json $(RUNNER) /testcases/pass.3 /dotnet-lib-release/
	$(MYST_EXEC) $(OPTS) $(ROOTFS) --app-config-path config.json $(RUNNER) /testcases/pass.4 /dotnet-lib-release/
	$(MYST_EXEC) $(OPTS) $(ROOTFS) --app-config-path config.json $(RUNNER) /testcases/pass.5 /dotnet-lib-release/

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) $(ROOTFS) --app-config-path config.json $(RUNNER) /$(TESTCASE) /dotnet-lib-release/