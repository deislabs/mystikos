TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS += mhsm_ssr

.PHONY: $(DIRS)

build: $(DIRS)

$(DIRS):
	@ $(MAKE) -C $@

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

ifdef MYST_DO_CLEANUP
remove_appdir = rm -rf $(1)/appdir $(1)/rootfs
else
remove_appdir =
endif

run:
	@ $(foreach i, $(DIRS), TESTDIR=$(BUILDDIR)/solutions $(MAKE) -C $(i) run; $(call remove_appdir,$(i)) $(NL) )

tests:
	@ $(MAKE) -s clean
	@ sudo rm -rf $(TESTDIR)
	@ $(MAKE) -j -s build
	@ $(MAKE) -j run
