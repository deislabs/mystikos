TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs
ROOTHASH=$(SUBOBJDIR)/roothash

LIBCXX_TESTS_DIR=llvm-project/libcxx/test/

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
	$(MAKE) $(ROOTHASH)

one:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) $(TEST)

llvm-project: 
	git clone -b LibOS_v10.0.1 --single-branch https://github.com/salsal97/llvm-project.git

libcxx-tests:
	mkdir libcxx-tests
	find $(LIBCXX_TESTS_DIR) -name \*pass.cpp -exec cp --parent {}  libcxx-tests \; 
	find $(LIBCXX_TESTS_DIR) -name \*.h -exec cp --parent {}  libcxx-tests \;

	# MAKE A LIST OF ALL THE TESTS
	find $(LIBCXX_TESTS_DIR) -name \*pass.cpp > $(ALLTESTS)
	sed -i 's/libcxx-tests\/llvm-project\/libcxx\/test\///g' $(ALLTESTS)
	sed -i -e 's/^/\/app\//' $(ALLTESTS)

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(APPDIR):
	$(APPBUILDER) -i mystikos/libcxx2_tests_10x:0.1
	cp $(CURDIR)/testsa*.passed $(APPDIR)
	# To build a new image, modify the appbuilder script to build the image with the correct name, 
	# and not clean it up. Then once the image is built, push it to dockerhub and update 
	# this call.

$(ROOTFS): run.c
	sudo $(MYST) mkext2 $(APPDIR) $(ROOTFS)
	# run with posix spawn

$(ROOTHASH): run.c
	mkdir -p $(SUBOBJDIR)
	$(MYST) fssig --roothash $(ROOTFS) > $(ROOTHASH)

OPTS += --roothash=$(ROOTHASH)

OPTS += --memory-size=1024m

tests:
	$(RUNTEST) $(MAKE) __tests

__tests:
	for i in a b c d e f g h i j k l m n o p ; do \
		$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run testsa$$i.passed ; \
	done

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS) $(ROOTHASH) testsa*

# Use to run passed + failed tests
runall:
	./run_tests_locally.sh $(ALLTESTS)

# Splits tests into batches for easy processing 
split: clean-tests
	split -l 140 alltests tests
	for i in a b c d e f g h i j k l m n o p ; do \
		grep -Fxf libcxx_passed testsa$$i > testsa$$i.passed ; \
	done

# Removes all the passed tests from all the tests to give us a list of failed ones
failed:
	comm -23 $(ALLTESTS) tests.passed > tests.failed

# Use to find flaky tests
repeat:
	while true; do make tests >> output ; done

# Use to order tests and remove flaky ones
clean-tests:
	sort -o $(ALLTESTS) $(ALLTESTS)
	sort -o libcxx_passed tests.passed
	sort -o libcxx_failed tests.failed
	sort -o libcxx_failedubuntu tests.failedubuntu
	comm -23 $(ALLTESTS) tests.remove > temp
	mv temp alltests
	comm -23 libcxx_passed tests.remove > temp
	mv temp libcxx_passed
	comm -23 libcxx_failed tests.failedubuntu > temp
	mv temp libcxx_failed
