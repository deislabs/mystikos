SUBDIR = samples
TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS = run echo lthread wake

include $(TOP)/rules.mak

tests:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )
