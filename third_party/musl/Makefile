TOP = $(abspath $(CURDIR)/../..)
include $(TOP)/defs.mak

DIRS = pristine crt

include $(TOP)/rules.mak

distclean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )
