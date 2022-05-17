TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

OPTS = --nobrk

ifdef STRACE
OPTS += --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile
	# Remove the test that depends on mmap(MAP_SHARED...).
	rm appdir/usr/local/lib/python3.9/site-packages/numpy/core/tests/test_memmap.py
	# Remove the test that fails due to rng
	rm appdir/usr/local/lib/python3.9/site-packages/numpy/core/tests/test_multiarray.py
	# Removing test failing due to no SYS_listxattr support
	rm appdir/usr/local/lib/python3.9/site-packages/numpy/core/tests/test_limited_api.py

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

run: rootfs
	TIMEOUT=150s $(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python3 /app/app.py

one: rootfs
	$(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /usr/local/bin/python3 -m pytest /usr/local/lib/python3.9/site-packages/$(TEST)

clean:
	rm -rf rootfs appdir .pytest_cache
