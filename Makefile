.PHONY: openenclave

BUILD_DIR=${CURDIR}/build

all: submodules openenclave samples

##==============================================================================
##
## submodules:
##
##==============================================================================

submodules:
	git submodule update --recursive --init --progress

##==============================================================================
##
## openenclave:
##
##==============================================================================

openenclave:
	$(MAKE) -C third_party/openenclave

clean:
	$(MAKE) -C third_party/openenclave clean
