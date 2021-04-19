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
# temporary ban dotnet test for code coverage due to the gcov infra (malcode filename) bug
ifndef MYST_ENABLE_GCOV
DIRS += dotnet
DIRS += aspnet
# Run coreclr tests only in nightly pipeline
ifdef RUN_CORECLR_TESTS
DIRS += coreclr
endif
endif

ifdef RUN_AZURE_TESTS
DIRS = dotnet_azure_sdk/Identity_Resource_Management_and_Storage dotnet_azure_sdk/KeyVault_Keys dotnet_azure_sdk/KeyVault_Secrets dotnet_azure_sdk/KeyVault_Certificates
endif

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
