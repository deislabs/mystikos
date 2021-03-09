.NOTPARALLEL:

TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=myst-alpine

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir

ROOTFS=$(CURDIR)/rootfs

##==============================================================================
##
## all rule:
##
##==============================================================================

all: $(APPDIR) $(APPDIR)/target $(APPDIR)/bin/run $(ROOTFS)

$(APPDIR):
	rm -rf $(APPDIR)
	cp -r $(TOP)/third_party/libc-test/libc-test $(APPDIR)
	cp $(CURDIR)/passed.txt $(APPDIR)
	cp $(CURDIR)/failed.txt $(APPDIR)

$(APPDIR)/target:
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -j -C appdir"
	touch $(APPDIR)/target

ifdef FAILED
  TEST_FILE = failed.txt
  STATUS=FAILED
  export TIMEOUT=10
else
  TEST_FILE = passed.txt
  STATUS=PASSED
endif

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(ROOTFS): run.c
	sudo $(MYST) mkext2 --force $(APPDIR) $(ROOTFS)
	sudo truncate --size=-4096 $(ROOTFS)

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
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run $(STATUS) $(TEST_FILE)

clean:
	rm -rf $(APPDIR) $(ROOTFS)
