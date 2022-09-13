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
TEST = /usr/local/lib/python3.9/site-packages/pandas/tests/io/test_fsspec.py 
TIMEOUT = 3000
# The following tests used to pass in mystikos, but currently hang indefinitely.
# Removing these tests currently, and will be added back after investigating
# these failures.
REMOVE_TESTS_TEMPORARILY= \
/usr/local/lib/python3.9/site-packages/pandas/tests/io/test_user_agent.py \

#the folllowing tests hang when run sequentially, but pass when run individually
TEST_RUN_INDIVIDUAL=$(shell cat tests.individual)

OPTS = --max-affinity-cpus=4 --app-config-path config.json
ifdef STRACE
OPTS += --strace
endif

all: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile
	cp $(PYTEST_INI_FILE) appdir/
	@ $(foreach i, $(REMOVE_TESTS_TEMPORARILY),  rm  -rf appdir/$(i) )

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

rootfs-passed: appdir
	# remove test files that are known to fail partially. These are tested in target 'run'
	# for expected failures/ errors.
	cat tests.partially_passed | while read line; do rm -f appdir/"$$line"; done
	# This file is temporarily being disabled from pandas_tests, to investigate handling
	@ $(foreach i, $(TEST_RUN_INDIVIDUAL),  rm  -rf appdir/$(i) )
	$(MYST) mkext2 appdir rootfs-passed

run-passed: rootfs-passed
	$(MYST_EXEC) rootfs-passed $(OPTS) $(PYTHON3) /app/app.py

run-individual: rootfs
	$(foreach i, $(TEST_RUN_INDIVIDUAL), echo $i; $(MAKE) run-one TEST=$(i) $(NL) )

run-partial: rootfs
	-(cat tests.partially_passed | xargs -P 8 $(MYST_EXEC) rootfs $(OPTS) \
		$(PYTEST_CMD) $(PYTEST_OPTS) 2>&1 > result; true)
	sed -i '$$d' result
	tail -n 26 result > test_summary
	diff -B -w test_summary expected-test-summary

_run: rootfs
	$(MAKE) run-partial
	$(MAKE) run-individual
	$(MAKE) clean_intermediate
	$(MAKE) run-passed
	$(MAKE) clean_intermediate
	
run:
	TIMEOUT=$(TIMEOUT) $(RUNTEST) make -C $(CURDIR) _run 

run-one: rootfs
	$(MYST_EXEC) rootfs $(OPTS) $(PYTEST_CMD) $(TEST)

clean_intermediate:
	rm -rf rootfs .pytest_cache result test_summary

clean:
	$(MAKE) clean_intermediate
	rm -rf myst rootfs rootfs-passed appdir
