TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS = --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

LIBCXX_TESTS_DIR=llvm-project/libcxx/test/

TEST_FILE = builttests_exe.passed
TESTS = $(shell cat $(TEST_FILE))

all: clean myst appdir rootfs

libcxx-tests: llvm-project
	mkdir libcxx-tests
	find $(LIBCXX_TESTS_DIR) -name \*pass.cpp -exec cp --parent {}  libcxx-tests \; 
	find $(LIBCXX_TESTS_DIR) -name \*.h -exec cp --parent {}  libcxx-tests \; 
	
	# copy all test names
	find $(LIBCXX_TESTS_DIR) -name \*pass.cpp > alltests.txt 

	sed -i 's/libcxx-tests\/llvm-project\/libcxx\/test\///g' alltests.txt
	sed -i -e 's/^/\/app\//' alltests.txt
	sed 's/$$/.exe/g' alltests.txt > alltests_exe.txt

	START=$(pwd)
	cd libcxx-tests/llvm-project/libcxx/test
	TEST_DIR=$(pwd)
	find . -type d > dirs.txt

	for dir in $(cat dirs.txt); \
    do cd $(dir) && echo $(dir); \
    for f in $(ls | grep pass.cpp); \
        do echo $(f) && g++ -g -I$(TEST_DIR)/support -fPIC -Wall -o $( basename ${f}.exe) $(f); \
        done; \
    cd $(TEST_DIR) ; \
    done;

	cd $(START)/libcxx-tests
	find $(LIBCXX_TESTS_DIR) -name \*pass.cpp.exe > builttests_exe.txt
	sed -i -e 's/^/\/app\//' builttests_exe.txt

llvm-project: 
	git clone -b LibOS_v10.0.1 --single-branch https://github.com/salsal97/llvm-project.git

appdir: 
	$(APPBUILDER) sagoel/libcxx_10x:0.1
	$(MAKE) patch_appdir
	# To build a new image, modify the appbuilder script to build the image with the correct name, 
	# and not clean it up. Then once the image is built, push it to dockerhub and update 
	# this call.

patch_appdir:
	rm -rf appdir/usr/lib/libstdc++.so.6
	cp appdir/usr/lib/libstdc++.so.6.0.28 appdir/usr/lib/libstdc++.so.6

rootfs:
	sudo $(MYST) mkext2 --force appdir rootfs
	$(MYST) fssig --roothash rootfs > roothash
	# run with posix spawn

tests:
	$(foreach i, $(TESTS), TESTNAME=$(TESTNAME)$(i)$(TESTSUFFIX) $(RUNTEST_COMMAND) $(MYST_EXEC) rootfs --roothash=roothash $(i) $(NL))

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf rootfs roothash appdir
	# libcxx-tests
