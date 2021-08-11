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
TEST = test_grammar
FS=ext2fs

# Set timeout to 10 mins
export TIMEOUT=600

all: ext2fs

appdir:
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

clean:
	rm -fr appdir ext2fs @test_101* hostfs

tests:
	$(RUNTEST) ./exec.sh

run-list: $(FS)
	$(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test -f $(TESTFILE) --timeout 30 -q

one: $(FS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TEST) -q
