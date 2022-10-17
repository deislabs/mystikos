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

#DIRS += mhsm_ssr
DIRS += msgpack_c

DIRS += dotnet
DIRS += aspnet_core
DIRS += numpy_core_tests
DIRS += cpython-tests

DIRS += memcached
DIRS += python_flask_tests
DIRS += python_web_frameworks
DIRS += python_webserver
ifndef MYST_SKIP_PR_TEST
# Do not run in PR pipeline as it takes ~15min
DIRS += tensorflow_lite
DIRS += pandas_tests
endif
DIRS += nodejs
DIRS += redis

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
	@ $(foreach i, $(DIRS), TESTDIR=$(BUILDDIR)/solutions $(MAKE) -C $(i) run; $(call remove_appdir,$(i)) $(NL) )

tests:
	@ $(MAKE) -s clean
	@ sudo rm -rf $(TESTDIR)
	@ $(MAKE) -j -s build
	@ $(MAKE) -j run
