TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
HEAP_SIZE="1G"
OPTS += --memory-size $(HEAP_SIZE)
ifdef STRACE
OPTS += --strace
endif
OPTS += --fork-mode pseudo_wait_for_exit_exec
TC = test_grammar

all: ext2fs

appdir:
	$(APPBUILDER) -i vtikoo/cpython:3.8-ubuntu

ext2fs: appdir
	$(MYST) mkext2 appdir ext2fs

clean:
	rm -fr appdir ext2fs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m test -f pass-list -q

run-single:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m test $(TC) -q

pdb:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) ext2fs /cpython/python -m pdb /cpython/Lib/test/test_grammar.py -v 

ct:
	rm -rf /tmp/myst*