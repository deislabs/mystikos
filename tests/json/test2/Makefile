TOP=$(abspath ../../..)
include $(TOP)/defs.mak

PROGRAM = jsontest2

SOURCES = $(wildcard *.c)

INCLUDES = -I$(INCDIR)

CFLAGS = $(OEHOST_CFLAGS) $(GCOV_CFLAGS)

LDFLAGS = $(OEHOST_LDFLAGS) $(GCOV_LDFLAGS)

LIBS += $(LIBDIR)/libmysthost.a
LIBS += $(LIBDIR)/libjson.a
LIBS += $(LIBDIR)/libmystutils.a

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(RUNTEST) $(MAKE) test-a
	$(RUNTEST) $(MAKE) test-b

test-a:
	@ $(eval TMP1 := $(shell /bin/mktemp))
	@ $(SUBBINDIR)/jsontest2 sample.json > $(TMP1)
	@ diff ${TMP1} expected.sample.json
	@ echo "=== passed test ($(__PROGRAM): test-a)"

test-b:
	@ $(eval TMP2 := $(shell /bin/mktemp))
	@ $(SUBBINDIR)/jsontest2 array.json > $(TMP2)
	@ diff ${TMP2} expected.array.json
	@ echo "=== passed test ($(__PROGRAM): test-b)"
