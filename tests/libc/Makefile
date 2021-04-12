.NOTPARALLEL:

TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=myst-alpine

ifdef STRACE
OPTS = --strace
endif

OPTS += --memory-size=256m

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

TEST_FILE = tests_passed.txt

##==============================================================================
##
## all rule:
##
##==============================================================================

all: $(APPDIR) $(APPDIR)/target $(APPDIR)/bin/run $(ROOTFS)

$(APPDIR):
	rm -rf $(APPDIR)
	cp -r $(TOP)/third_party/libc-test/libc-test $(APPDIR)
	cp $(CURDIR)/$(TEST_FILE) $(APPDIR)

$(APPDIR)/target:
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -j -C appdir"
	touch $(APPDIR)/target

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(ROOTFS): run.c
	sudo $(MYST) mkext2 --force $(APPDIR) $(ROOTFS)
	truncate --size=-4096 $(ROOTFS)

##==============================================================================
##
## tests:
##
##==============================================================================

RUN = $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS)

ifdef TEST
one:
	$(RUNTEST) $(MYST_EXEC) rootfs $(OPTS) $(TEST)
endif

tests: all
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run $(TEST_FILE)

clean:
	rm -rf $(APPDIR) $(ROOTFS)
