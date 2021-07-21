TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="4G"
OPTS += --memory-size $(HEAP_SIZE)
ifdef STRACE
OPTS += --strace
endif
OPTS += --fork-mode pseudo_wait_for_exit_exec
TESTFILE=tests.passed
TC = test_grammar

# Set timeout to 10 mins
export TIMEOUT=600

all: ext2fs

appdir:
	$(APPBUILDER) Dockerfile

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

clean:
	rm -fr appdir ext2fs @test_101*

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m test -f tests.passed -q
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m test -f tests.passed.1 -q

run-single:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m test $(TC) -v

run-str:
	$(MYST_EXEC) $(OPTS) ext2fs /cpython/python -c "$(PROG_STR)"

pdb:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m pdb /cpython/Lib/test/test_grammar.py -v 

ct:
	rm -rf /tmp/myst*