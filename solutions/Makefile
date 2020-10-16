TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =
DIRS += attested_tls
DIRS += sql_ae
DIRS += msgpack_c

REDEFINE_TESTS=1
include $(TOP)/rules.mak

__clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

__build:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

__run:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NL) )

tests:
	@ $(MAKE) -s __clean 
	@ $(MAKE) -s __build 
	@ $(MAKE) -s __run
