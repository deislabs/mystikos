.NOTPARALLEL:
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
ifdef FAILED
  TEST_FILE1 = builttests_exe.failed
  STATUS=FAILED
  export TIMEOUT=10
else
  TEST_FILE1 = builttests_exe1.passed
  TEST_FILE2 = builttests_exe2.passed
  TEST_FILE3 = builttests_exe3.passed
  STATUS=PASSED
  export TIMEOUT=10000
endif

all:
	$(MAKE) clean
	$(MAKE) myst
	$(MAKE) $(APPDIR)
	$(MAKE) $(APPDIR)/bin/run
	$(MAKE) $(ROOTFS)
	$(MAKE) $(ROOTHASH)

one:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) $(TEST)

llvm-project: 
	git clone -b LibOS_v10.0.1 --single-branch https://github.com/salsal97/llvm-project.git

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(APPDIR):
	$(APPBUILDER) mystikos/libcxx_tests_10x:1.1
	cp $(CURDIR)/builttests_exe1.passed $(APPDIR)
	cp $(CURDIR)/builttests_exe2.passed $(APPDIR)
	cp $(CURDIR)/builttests_exe3.passed $(APPDIR)
	cp $(CURDIR)/builttests_exe.failed $(APPDIR)
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

__tests: test1 test2 test3

test1:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run $(STATUS) $(TEST_FILE1)

test2:
ifndef FAILED
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run $(STATUS) $(TEST_FILE2)
endif

test3:
ifndef FAILED
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run $(STATUS) $(TEST_FILE3)
endif

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS) $(ROOTHASH)
