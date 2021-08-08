.NOTPARALLEL:
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs

LIBCXX_TESTS_DIR=llvm-project/libcxx/

# batching passed testfiles here helps to remove large heap memory requirement from 3gb 
# to 1gb
ALLTESTS=tests.all
export TIMEOUT=10000

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
	$(APPBUILDER) -i mystikos/libcxx_11x:0.1
	cp $(CURDIR)/testsa*.passed $(APPDIR)
	cp $(CURDIR)/tests.passed $(APPDIR)
	# To build a new image, modify the appbuilder script to build the image with the correct name, 
	# and not clean it up. Then once the image is built, push it to dockerhub and update 
	# this call.

$(ROOTFS): run.c
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

OPTS += --memory-size=1024m

tests:
	$(RUNTEST) $(MAKE) __tests

__TESTS=a b c d e f g h i j k l m n o
.PHONY: $(__TESTS)

__tests: $(__TESTS)

$(__TESTS):
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run testsa$@.passed

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS) testsa* *.sorted

# Use to run passed + failed tests
runall:
	./run_tests_locally.sh $(ALLTESTS)

# Splits tests into batches for easy processing 
split: clean-tests
	split -l 320 $(ALLTESTS) tests
	for i in $(__TESTS) ; do \
		grep -Fxf libcxx_passed testsa$$i > testsa$$i.passed ; \
	done

# Removes all the passed tests from all the tests to give us a list of failed ones
failed:
	comm -23 $(ALLTESTS) tests.passed > tests.failed

# Use to find flaky tests
repeat:
	touch output
	rm output
	while true; do make tests >> output ; done

# Use to order tests and remove flaky ones
clean-tests:
	sort -o $(ALLTESTS).sorted $(ALLTESTS)
	sort -o tests.passed.sorted tests.passed
	sort -o tests.failed.sorted tests.failed
	sort -o tests.failedalpine.sorted tests.failedalpine
	sort -o tests.remove.sorted tests.remove
	comm -23 $(ALLTESTS).sorted tests.remove.sorted > alltests
	comm -23 tests.passed.sorted tests.remove.sorted > libcxx_passed
	comm -23 tests.failed.sorted tests.failedalpine.sorted > libcxx_failed

allinone:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) --nobrk /bin/run /tests.passed
