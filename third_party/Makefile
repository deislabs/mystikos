TOP = $(abspath $(CURDIR)/..)
include $(TOP)/defs.mak

DIRS = openenclave musl mbedtls libc-test gcompat

.PHONY: $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )

init:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) $(i) $(NL) )
	$(MAKE) -B -C openenclave openenclave

build:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) build $(NL) )
