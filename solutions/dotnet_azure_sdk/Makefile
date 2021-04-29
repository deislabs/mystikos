TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS = 
DIRS += Identity_Resource_Management_and_Storage
DIRS += KeyVault_Keys
DIRS += KeyVault_Secrets
DIRS += KeyVault_Certificates

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
	@ $(MAKE) -j -s __run
