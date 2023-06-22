TOP=$(abspath ../..)
include $(TOP)/defs.mak 

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

all: build

build: appdir rootfs

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkcpio appdir rootfs

run:
	$(RUNTEST) $(MYST_EXEC) --app-config-path config.json $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest 

run_single:
# Run single test for debugging
	$(RUNTEST) $(MYST_EXEC) --app-config-path config.json $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest tests/test_instance_config.py::test_egg_installed_paths

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) --app-config-path config.json $(OPTS) rootfs /usr/local/bin/python /usr/local/bin/pytest tests/test_instance_config.py::test_egg_installed_paths

clean:
	rm -rf appdir rootfs
