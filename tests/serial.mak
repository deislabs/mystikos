ifndef PARALLEL
.NOTPARALLEL:
endif

MYST_NIGHTLY_TEST=1

ifdef MYST_NIGHTLY_TEST
DIRS = cpython-tests
endif

.PHONY: $(DIRS)

$(DIRS):
	@ echo ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
	$(MAKE) -C $@

tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
