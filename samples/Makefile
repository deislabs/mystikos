SUBDIR = samples
TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS = echo

include $(TOP)/rules.mak

tests:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )
