TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

LIBCXX_EXCEPTION_TESTS_DIR=$(TOP)/third_party/openenclave/openenclave/3rdparty/libcxx/libcxx/test/std/language.support/support.exception/
LIBCXX_EXCEPTION_HEADER_FILE=$(TOP)/third_party/openenclave/openenclave/3rdparty/libcxx/libcxx/test/support/test_macros.h

TEST_FILE = tests.txt
TESTS = $(shell cat $(TEST_FILE))

all: myst appdir rootfs

libcxx-tests:
	mkdir libcxx-tests
	# https://stackoverflow.com/questions/15617016/copy-all-files-with-a-certain-extension-from-all-subdirectories
	find $(LIBCXX_EXCEPTION_TESTS_DIR) -name \*.cpp -exec cp {}  libcxx-tests \;
	cp $(LIBCXX_EXCEPTION_HEADER_FILE) libcxx-tests

appdir: libcxx-tests
	$(APPBUILDER) Dockerfile

rootfs:
	$(BINDIR)/myst mkcpio appdir rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /app/basic-exceptions.cpp.exe $(OPTS)
	@ $(foreach i, $(TESTS), TESTNAME=$(TESTNAME)$(i)$(TESTSUFFIX) $(RUNTEST_COMMAND) $(MYST_EXEC) rootfs $(i) $(NL))

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs appdir libcxx-tests
