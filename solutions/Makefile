TOP=$(abspath ..)
include $(TOP)/defs.mak

DIRS =
DIRS += attested_tls

ifdef DB_SERVER_NAME
ifdef DB_NAME
ifdef MAA_URL
DIRS += sql_ae
DIRS += python_app
endif
endif
endif

# Enable this azure-specific solution only on the nightly pipeline
# as it depends on secrets only availale on that pipeline.
ifdef MYST_NIGHTLY_TEST
DIRS += mhsm_ssr
DIRS += confidential_ml
endif

DIRS += msgpack_c

ifndef MYST_ENABLE_GCOV
DIRS += dotnet
endif

DIRS += aspnet
DIRS += memcached
DIRS += python_flask_tests
DIRS += python_web_frameworks
DIRS += python_webserver
ifndef MYST_SKIP_PR_TEST
# Do not run in PR pipeline as it takes ~15min
DIRS += tensorflow_lite
DIRS += dotnet_lib
DIRS += pandas_tests
endif
DIRS += nodejs
DIRS += numpy_core_tests
DIRS += redis
DIRS += cpprestsdk

.PHONY: $(DIRS)

build: $(DIRS)

$(DIRS):
	@ $(MAKE) -C $@

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

ifdef MYST_DO_CLEANUP
remove_appdir = rm -rf $(1)/appdir $(1)/rootfs
else
remove_appdir =
endif

run:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run; $(call remove_appdir,$(i)) $(NL) )

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -j -s build
	@ $(MAKE) -j -s run
