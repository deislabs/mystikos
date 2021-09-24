TOP = $(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
PYTEST_INI_FILE = ../pytest.ini
TEST_ROOT = /usr/local/lib/python3.9/site-packages
TEST = numpy/core/tests/test_argparse.py

OPTS = --app-config-path config.json
ifdef STRACE
OPTS += --strace
endif

all: rootfs

rootfs: ../appdir
	# Remove the test that depends on mmap(MAP_SHARED...).
	rm -f ../appdir/usr/local/lib/python3.9/site-packages/numpy/core/tests/test_memmap.py
	# Remove the test that fails due to rng
	rm -f ../appdir/usr/local/lib/python3.9/site-packages/numpy/core/tests/test_multiarray.py
	$(MYST) mkext2 ../appdir rootfs

run: rootfs
	$(MYST_EXEC) rootfs $(OPTS) /usr/local/bin/python3 /app/numpy_app.py

one: rootfs
	$(MYST_EXEC) rootfs $(OPTS) /usr/local/bin/python3 -m pytest $(TEST_ROOT)/$(TEST)

clean:
	rm -rf rootfs .pytest_cache
