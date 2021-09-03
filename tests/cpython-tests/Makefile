TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="4G"
OPTS += --memory-size $(HEAP_SIZE) --nobrk
ifdef STRACE
OPTS += --strace
endif
OPTS += --fork-mode pseudo_wait_for_exit_exec
TESTFILE=tests.passed
TEST = test_ntpath
FS=ext2fs3.9

# Set timeout to 20 mins (to run both the python3.8 test suite and the python3.9 test suite)
export TIMEOUT=1200

all: ext2fs3.8 ext2fs3.9 

ext2fs3.8:
	rm -fr appdir3.8
	$(APPBUILDER) -o appdir3.8 Dockerfile 
	$(MYST) mkext2 appdir3.8 ext2fs3.8

ext2fs3.9:
	rm -fr appdir3.9
	$(APPBUILDER) -o appdir3.9 Dockerfile3.9
	$(MYST) mkext2 appdir3.9 ext2fs3.9

clean:
	rm -fr appdir* ext2fs* @test_101* hostfs

tests:
	$(RUNTEST) ./exec.sh

run-list: ext2fs3.8 ext2fs3.9
	$(MYST_EXEC) $(OPTS) ext2fs3.8 /cpython/python -m test -f $(TESTFILE) --timeout 30 -q
	$(MYST_EXEC) $(OPTS) ext2fs3.9 /cpython/python -m test -f $(TESTFILE) --timeout 30 -q

one: $(FS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TEST) -v
