# Some tests in files listed in tests.partially_passed fail/ error out on execution.
# These failures and error are caused by one of below:
# 1. pypaper linux specific errors, documented
# here - https://pyperclip.readthedocs.io/en/latest/#not-implemented-error
# 2. s3fs error (which is currently an optional file handling mechanism in pandas)
# https://bleepcoder.com/evalml/557744402/unit-test-fails-after-upgrading-to-pandas-1-0-0

TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
PYTHON3 = /usr/local/bin/python3
PYTEST_CMD = $(PYTHON3) -m pytest
PYTEST_INI_FILE = pytest.ini
PYTEST_OPTS = -s -q --no-header --skip-slow --skip-db --skip-network
TEST_ROOT = /usr/local/lib/python3.9/site-packages/
TEST = pandas/tests/arrays/string_/test_string.py

OPTS = --max-affinity-cpus=4 --app-config-path config.json
ifdef STRACE
OPTS += --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) Dockerfile
	cp $(PYTEST_INI_FILE) appdir/

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

rootfs-passed: appdir
	# remove test files that are known to fail partially. These are tested in target 'run'
	# for expected failures/ errors.
	cat tests.partially_passed | while read line; do rm -f appdir/"$$line"; done
	$(MYST) mkext2 appdir rootfs-passed

run-passed: rootfs-passed
	$(MYST_EXEC) rootfs-passed $(OPTS) $(PYTHON3) /app/app.py

run: rootfs
	-(cat tests.partially_passed | xargs -P 8 $(MYST_EXEC) rootfs $(OPTS) \
		$(PYTEST_CMD) $(PYTEST_OPTS) 2>&1 > result; true)
	sed -i '$$d' result
	tail -n 28 result > test_summary
	diff test_summary expected-test-summary
	$(MAKE) clean_intermediate
	$(MAKE) run-passed

run-one: rootfs
	# NOTE: This target is provided for debugging purposes only. It could fail
	# unexpectedly for few test files.
	# (e.g., pandas/tests/extension/arrow/arrays.py fails with
	# ModuleNotFoundError).
	$(MYST_EXEC) rootfs $(OPTS) $(PYTEST_CMD) $(PYTEST_OPTS) $(TEST_ROOT)/$(TEST)

clean_intermediate:
	rm -rf rootfs .pytest_cache result test_summary

clean:
	$(MAKE) clean_intermediate
	rm -rf myst rootfs rootfs-passed appdir
