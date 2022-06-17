TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

OPTS = --app-config-path config.json
ifdef TRACE
	OPTS += --strace --etrace
else
	ifdef STRACE
		OPTS += --strace
	endif
	ifdef ETRACE
		OPTS += --etrace
	endif
endif

MPDB=$(TOP)/scripts/mpdb.py
TESTFILE=tests.passed
TEST = test_sys
TESTCASE = test_urllib2_localnet.TestUrlopen.test_line_iteration
VER=3.10
FS=ext2fs$(VER)


TEST_RUN_INDIVIDUAL_3_8=$(shell cat test_config_v3.8.11/tests.passed.individual)
TEST_RUN_INDIVIDUAL_3_9=$(shell cat test_config_v3.9.7/tests.passed.individual)
TEST_RUN_INDIVIDUAL_3_10=$(shell cat test_config_v3.10.2/tests.passed.individual)

# Set timeout to 60 mins (to run both the python3.8, 3.9 and 3.10 test suite)
export TIMEOUT=3600

all: ext2fs3.10 
ifdef MYST_NIGHTLY_TEST
	$(MAKE) ext2fs3.9
	$(MAKE) ext2fs3.8
endif

mpdb.py:$(MPDB)
	cp -f $(TOP)/scripts/mpdb.py mpdb.py

ext2fs3.8:mpdb.py test_config_v3.8.11/tests.passed
	rm -fr appdir3.8
	$(APPBUILDER) -m -o appdir3.8 -e "--build-arg CPYTHON_TAG=v3.8.11" Dockerfile
	$(MYST) mkext2 -f appdir3.8 ext2fs3.8

ext2fs3.9:mpdb.py test_config_v3.9.7/tests.passed
	rm -fr appdir3.9
	$(APPBUILDER) -m -o appdir3.9 -e "--build-arg CPYTHON_TAG=v3.9.7" Dockerfile
	$(MYST) mkext2 -f appdir3.9 ext2fs3.9

appdir3.10: mpdb.py
	$(APPBUILDER) -m -o appdir3.10 -e "--build-arg CPYTHON_TAG=v3.10.2" Dockerfile
ext2fs3.10: appdir3.10
	$(MYST) mkext2 -f appdir3.10 ext2fs3.10

clean:
	rm -fr appdir* ext2fs* @test_101* hostfs

run:
	$(MAKE) run-3.10
ifdef MYST_NIGHTLY_TEST
	$(MAKE) run-3.9
	$(MAKE) run-3.8
endif

run-3.8: ext2fs3.8
	SUBTEST=$(TESTFILE)-3.8 $(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs3.8 /cpython/python -m test -f /$(TESTFILE) --timeout 120 -v
	$(foreach i, $(TEST_RUN_INDIVIDUAL_3_8), $(MAKE) one FS=ext2fs3.8 TEST=$(i) $(NL) )

run-3.9: ext2fs3.9
	SUBTEST=$(TESTFILE)-3.9 $(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs3.9 /cpython/python -m test -f /$(TESTFILE) --timeout 120 -v
	$(foreach i, $(TEST_RUN_INDIVIDUAL_3_9), $(MAKE) one FS=ext2fs3.9 TEST=$(i) $(NL) )

run-3.10: ext2fs3.10
	SUBTEST=$(TESTFILE)-3.10 $(RUNTEST) $(MYST_EXEC) --app-config-path config-3.10.json ext2fs3.10 /cpython/python -m test -f /$(TESTFILE) --timeout 120 -v
	$(foreach i, $(TEST_RUN_INDIVIDUAL_3_10), $(MAKE) one FS=ext2fs3.10 TEST=$(i) $(NL) )

one:
	SUBTEST=$(TEST)-$(FS) $(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TEST) -v

one-mpdb:
	killall myst 2> /dev/null || echo ""
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m mpdb -m test $(TEST) -v &
	sleep 15 # Increase this value in Makefile if connection fails
	rlwrap telnet 127.0.0.1 5678
	# Once debugger prompt is available, do
	# (Pdb) b /cpython/Lib/test/<test file>.py:line

one-gdb:
	$(RUNTEST) $(MYST_GDB) -iex "source ./appdir$(VER)/cpython/python-gdb.py" \
           -iex "python print('\033[0;32m\n\
type py-<tab> to see available python-gdb commands.\n\n\
To enable python source listing, do \n\
  sudo mkdir -p /cpython\n\
  sudo mount --bind appdir$(VER)/cpython /cpython\n\
before launching gdb.\033[0m\n')" \
           --args $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TEST) -v

testcase:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m unittest Lib.test.$(TESTCASE) -v

testcase-gdb:
	$(RUNTEST) $(MYST_GDB) -iex "source ./appdir$(VER)/cpython/python-gdb.py" \
           -iex "python print('\033[0;32m\n\
type py-<tab> to see available python-gdb commands.\n\n\
To enable python source listing, do \n\
  sudo mkdir -p /cpython\n\
  sudo mount --bind appdir$(VER)/cpython /cpython\n\
before launching gdb.\033[0m\n')" \
           --args $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m unittest Lib.test.$(TESTCASE) -v

testcase-mpdb:
	killall myst 2> /dev/null || echo ""
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m mpdb -m unittest Lib.test.$(TESTCASE) -v &
	sleep 15 # Increase this value in Makefile if connection fails
	rlwrap telnet 127.0.0.1 5678
	# Once debugger prompt is available, do
	# (Pdb) b /cpython/Lib/test/<test file>.py:line

CPYTHON_TAG=v3.8.11
apply-patch:
	git clone --depth 1 --single-branch --branch $(CPYTHON_TAG) https://github.com/python/cpython.git cpython_$(CPYTHON_TAG)
	cp test_config_$(CPYTHON_TAG)/patch cpython_$(CPYTHON_TAG)
	cd cpython_$(CPYTHON_TAG) && git apply patch

gen-patch:
	cd cpython_$(CPYTHON_TAG) && git diff > ../test_config_$(CPYTHON_TAG)/patch
