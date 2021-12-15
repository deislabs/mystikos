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
TEST = test_regrtest
TESTCASE = test_glob.GlobTests.test_recursive_glob
TESTCASE = test_socket.SendmsgUnixStreamTest.testSendmsgDontWait
VER=3.9
FS=ext2fs$(VER)

# Set timeout to 50 mins (to run both the python3.8 test suite and the python3.9 test suite)
export TIMEOUT=3000

all: ext2fs3.8 ext2fs3.9 ext2fs3.10

mpdb.py:$(MPDB)
	cp -f $(TOP)/scripts/mpdb.py mpdb.py

ext2fs3.8:mpdb.py
	rm -fr appdir3.8
	$(APPBUILDER) -o appdir3.8 -e "--build-arg CPYTHON_VERSION=v3.8.11" Dockerfile
	$(MYST) mkext2 -f appdir3.8 ext2fs3.8

ext2fs3.9:mpdb.py
	rm -fr appdir3.9
	$(APPBUILDER) -o appdir3.9 -e "--build-arg CPYTHON_VERSION=v3.9.7" Dockerfile
	$(MYST) mkext2 -f appdir3.9 ext2fs3.9

ext2fs3.10:mpdb.py
	# rm -fr appdir3.10
	# $(APPBUILDER) -o appdir3.10 -e "--build-arg CPYTHON_VERSION=v3.10.0" Dockerfile
	$(MYST) mkext2 -f appdir3.10 ext2fs3.10

clean:
	rm -fr appdir* ext2fs* @test_101* hostfs

tests:
	$(RUNTEST) ./exec.sh

run-list: ext2fs3.8 ext2fs3.9 ext2fs3.10
	$(MYST_EXEC) $(OPTS) ext2fs3.8 /cpython/python -m test -f /$(TESTFILE) --timeout 120 -q
	$(MYST_EXEC) $(OPTS) ext2fs3.9 /cpython/python -m test -f /$(TESTFILE) --timeout 120 -q
	$(MYST_EXEC) $(OPTS) ext2fs3.10 /cpython/python -m test -f /$(TESTFILE) --timeout 120 -q

one: $(FS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TEST) -v

one-mpdb: $(FS)
	killall myst 2> /dev/null || echo ""
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m mpdb -m test $(TEST) -v &
	sleep 15 # Increase this value in Makefile if connection fails
	rlwrap telnet 127.0.0.1 5678
	# Once debugger prompt is available, do
	# (Pdb) b /cpython/Lib/test/<test file>.py:line

one-gdb: $(FS)
	$(RUNTEST) $(MYST_GDB) -iex "source ./appdir$(VER)/cpython/python-gdb.py" \
           -iex "python print('\033[0;32m\n\
type py-<tab> to see available python-gdb commands.\n\n\
To enable python source listing, do \n\
  sudo mkdir -p /cpython\n\
  sudo mount --bind appdir$(VER)/cpython /cpython\n\
before launching gdb.\033[0m\n')" \
           --args $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TEST) -v

testcase: $(FS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m unittest Lib.test.$(TESTCASE) -v

testcase-gdb: $(FS)
	$(RUNTEST) $(MYST_GDB) -iex "source ./appdir$(VER)/cpython/python-gdb.py" \
           -iex "python print('\033[0;32m\n\
type py-<tab> to see available python-gdb commands.\n\n\
To enable python source listing, do \n\
  sudo mkdir -p /cpython\n\
  sudo mount --bind appdir$(VER)/cpython /cpython\n\
before launching gdb.\033[0m\n')" \
           --args $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m unittest Lib.test.$(TESTCASE) -v
