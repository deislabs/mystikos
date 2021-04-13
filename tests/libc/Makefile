TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=myst-alpine

ifdef STRACE
OPTS = --strace
endif

OPTS += --memory-size=8m
OPTS += --max-threads=16

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

TEST_FILE = tests_passed.txt

export TIMEOUT=120

##==============================================================================
##
## all rule:
##
##==============================================================================

all:
	$(MAKE) $(APPDIR)
	$(MAKE) $(APPDIR)/target
	$(MAKE) $(APPDIR)/bin/run
	$(MAKE) $(ROOTFS)

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

tests:
	$(MAKE) -j __tests

__tests: tests_01 tests_02 tests_03 tests_04 tests_05 tests_06

run=$(foreach i,$1, ( $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) $(i) || /bin/false ) ; $(NL) )

tests_01:
	$(call run,$(shell cat $(TEST_FILE).01))

tests_02:
	$(call run,$(shell cat $(TEST_FILE).02))

tests_03:
	$(call run,$(shell cat $(TEST_FILE).03))

tests_04:
	$(call run,$(shell cat $(TEST_FILE).04))

tests_05:
	$(call run,$(shell cat $(TEST_FILE).05))

tests_06:
	$(call run,$(shell cat $(TEST_FILE).06))

OLD_OPTS =

old-tests: all
	$(RUNTEST) $(MYST_EXEC) $(OLD_OPTS) $(ROOTFS) /bin/run $(TEST_FILE)

clean:
	rm -rf $(APPDIR) $(ROOTFS)

split:
	split --lines=50 --numeric-suffix=1 $(TEST_FILE) $(TEST_FILE).
