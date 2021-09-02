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
DIRS += python_webserver

ifndef MYST_ENABLE_GCOV
DIRS += dotnet
endif

DIRS += aspnet
DIRS += memcached
DIRS += python_web_frameworks
DIRS += nodejs
DIRS += numpy_core_tests
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
