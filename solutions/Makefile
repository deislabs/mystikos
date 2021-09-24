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
# Disable this as it fails pipeline, will re-enable after investigation
#DIRS += pytorch_inference
DIRS += tensorflow_lite
DIRS += numpy_pandas_tests
endif
DIRS += nodejs
DIRS += redis

.PHONY: $(DIRS)

build: $(DIRS)

$(DIRS):
	@ $(MAKE) -C $@

clean:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

run:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NL) )

tests:
	@ $(MAKE) -s clean
	@ $(MAKE) -j -s build
	@ $(MAKE) -j -s run
