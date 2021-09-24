TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
PYTEST_INI_FILE = pytest.ini

DIRS =
DIRS += pandas_tests
DIRS += numpy_core_tests

appdir:
	$(APPBUILDER) Dockerfile
	cp $(PYTEST_INI_FILE) appdir/

.PHONY: $(DIRS)

build: appdir $(DIRS)

$(DIRS):
	@ $(MAKE) -C $@

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
	rm -rf appdir

run:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NL) )

one:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NL) )

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -j -s build
	@ $(MAKE) -j -s run

