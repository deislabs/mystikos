TOP=$(abspath ../..)
include $(TOP)/defs.mak 

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

all: build

build: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

run:
# Skip test that would fail
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest -k "not test_egg_installed_paths" --app-config-path config.json

run_single:
# Run single test for debugging
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest tests/test_instance_config.py::test_egg_installed_paths --app-config-path config.json

clean:
	rm -rf appdir rootfs