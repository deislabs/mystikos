TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =
DIRS += attested_tls

ifdef DB_SERVER_NAME
ifdef DB_NAME
ifdef MAA_URL
DIRS += sql_ae
endif
endif
endif

DIRS += msgpack_c
DIRS += python_webserver

ifndef MYST_ENABLE_GCOV
DIRS += dotnet
endif

DIRS += aspnet

# Run coreclr tests only in nightly pipeline
ifdef RUN_CORECLR_TESTS
DIRS += coreclr
endif

DIRS += memcached

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
