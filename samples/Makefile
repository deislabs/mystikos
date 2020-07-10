TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS = echo

all:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

tests:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
