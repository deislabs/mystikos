TOP = $(abspath $(CURDIR)/..)
include $(TOP)/defs.mak

DIRS = openenclave musl mbedtls libc-test gcompat

include $(TOP)/rules.mak

distclean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )
