TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =

ifneq ($(TARGET),linux)
DIRS += tlscert2
endif

.PHONY: $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

ifdef MYST_DO_CLEANUP
remove_appdir = rm -rf $(1)/appdir
else
remove_appdir =
endif

__tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests; $(call remove_appdir,$(i)) $(NL) )

tests:
	@ sudo rm -rf $(TESTDIR)
	@ $(MAKE) __tests TARGET=sgx TESTSUFFIX=.sgx
	@ $(MAKE) __tests TARGET=linux TESTSUFFIX=.linux

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean: clean

pipe-tests:
	$(MAKE) -C pipe tests
	$(MAKE) -C pollpipe tests
	$(MAKE) -C pollpipe2 tests
	$(MAKE) -C spawn tests
	$(MAKE) -C spawnfa tests
	$(MAKE) -C ltp pipe-tests

pipe-build:
	$(MAKE) -C pipe
	$(MAKE) -C pollpipe
	$(MAKE) -C pollpipe2
	$(MAKE) -C spawn
	$(MAKE) -C spawnfa
	$(MAKE) -C ltp
