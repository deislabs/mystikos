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

DIRS += msgpack_c

ifndef MYST_ENABLE_GCOV
DIRS += dotnet
endif

DIRS += aspnet
DIRS += memcached
DIRS += python_web_frameworks
DIRS += python_webserver
ifndef MYST_SKIP_PR_TEST
# Do not run in PR pipeline as it takes ~15min
DIRS += pytorch_inference
endif
DIRS += nodejs
DIRS += numpy_core_tests
DIRS += redis

.PHONY: $(DIRS)

build: $(DIRS)

# If BUILD_RUN_CLEAN is set, then build/run/clean each test
# Otherwise, just build everything
ifdef BUILD_RUN_CLEAN
$(DIRS):
	@ $(MAKE) -C $@ && $(MAKE) -C $@ run && $(MAKE) -C $@ clean
else
$(DIRS):
	@ $(MAKE) -C $@
endif

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

run:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NL) )

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -j -s build
	@ $(MAKE) -j -s run

# Use in pipeline to save space
# This will build/run/clean each solution test before moving to next test
tests_clean:
	@ $(MAKE) -s clean
	@ $(MAKE) -j -s build BUILD_RUN_CLEAN=1
