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

LIBCXX_TESTS_DIR=llvm-project/libcxx/

# batching passed testfiles here helps to remove large heap memory requirement from 3gb 
# to 1gb
ALLTESTS=tests.all
export TIMEOUT=10000
OPTS += --nobrk

all:
	$(MAKE) myst
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
	$(APPBUILDER) -m -i mystikos/libcxx_11x:0.1
	cp $(CURDIR)/tests.passed $(APPDIR)
# To build a new image, push the new container to dockerhub and update 
# this call.

$(ROOTFS): run.c
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

OPTS += --memory-size=64m

tests: $(ROOTFS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run /tests.passed

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS)

# Use to run passed + failed tests
runall:
	./run_tests_locally.sh $(ALLTESTS)

# Removes all the passed tests from all the tests to give us a list of failed ones
failed:
	comm -23 $(ALLTESTS) tests.passed > tests.failed

# This crasshes with memcheck enabled
bug:
	make one TEST=/app/llvm-project/libcxx/test/libcxx/input.output/iostreams.base/ios/iostate.flags/clear.abort.pass.cpp.exe
