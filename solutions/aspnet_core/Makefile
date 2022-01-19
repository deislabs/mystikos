TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS =
DIRS += aspnet_minimal_server
DIRS += aspnet_samples

include $(TOP)/rules.mak

run:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NL) )
