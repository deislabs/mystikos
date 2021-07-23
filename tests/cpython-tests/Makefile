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

#########################
##	Dev targets
#########################
hostfs:
	cp -r appdir/ hostfs/

run-list: $(FS)
	$(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test -f $(TESTFILE) --timeout 30 -q


run-single: $(FS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m test $(TC) -q

run-str: $(FS)
	$(MYST_EXEC) $(OPTS) $(FS) /cpython/python -c "$(PROG_STR)"

pdb: $(FS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) /cpython/python -m pdb /cpython/Lib/test/test_grammar.py -v

ct:
	rm -rf /tmp/myst* @test_101*
