.NOTPARALLEL:
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs

LIBCXX_TESTS_DIR=llvm-project/libcxx/test/

# batching passed testfiles here helps to remove large heap memory requirement from 3gb 
# to 1gb
ALLTESTS=tests.all
export TIMEOUT=10000
OPTS += --nobrk

all:
	$(MAKE) myst
	$(MAKE) split
	$(MAKE) $(APPDIR)
	$(MAKE) $(APPDIR)/bin/run
	$(MAKE) $(ROOTFS)

one:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) $(TEST)

llvm-project: 
	git clone -b myst_v11.0.1 --single-branch https://github.com/salsal97/llvm-project.git

libcxx-tests: llvm-project
	mkdir libcxx-tests
	find $(LIBCXX_TESTS_DIR) -name \*pass.cpp -exec cp --parent {}  libcxx-tests \; 
	find $(LIBCXX_TESTS_DIR) -name \*.h -exec cp --parent {}  libcxx-tests \;

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(APPDIR):
	$(APPBUILDER) -m -i mystikos/libcxx2_11x:0.1
	cp $(CURDIR)/testsa*.passed $(APPDIR)
# To build a new image, push the new container to dockerhub and update 
# this call.

$(ROOTFS): run.c
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

OPTS += --memory-size=1536m

tests:
	$(RUNTEST) $(MAKE) __tests

__tests:
	for i in a b c d e f ; do \
		$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run testsa$$i.passed ; \
	done

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS) testsa*

# Use to run passed + failed tests
runall:
	./run_tests_locally.sh $(ALLTESTS)

# Splits tests into batches for easy processing 
split: clean-tests
	split -l 900 $(ALLTESTS) tests
	for i in a b c d e f ; do \
		grep -Fxf libcxx_passed testsa$$i > testsa$$i.passed ; \
	done

# Removes all the passed tests from all the tests to give us a list of failed ones
failed:
	comm -23 $(ALLTESTS) tests.passed > tests.failed

# Use to find flaky tests
repeat:
	touch output
	rm output
	while true; do make tests >> output ; echo "finish"; done

# Use to order tests and remove flaky ones
clean-tests:
	sort -o $(ALLTESTS) $(ALLTESTS)
	sort -o tests.passed tests.passed
	sort -o tests.failed tests.failed
	sort -o tests.failedubuntu tests.failedubuntu
	sort -o tests.remove tests.remove
	comm -23 $(ALLTESTS) tests.remove > alltests
	comm -23 tests.passed tests.remove > libcxx_passed
	comm -23 tests.failed tests.failedubuntu > libcxx_failed
